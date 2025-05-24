/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* complex.c
** libstrophe XMPP client library -- more complex usage example
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT or GPLv3 licenses.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <conio.h>
#include <ctype.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h> /* tcp_keepalive */
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#include <strophe.h>

/* hardcoded TCP keepalive timeout and interval */
#define KA_TIMEOUT 60
#define KA_INTERVAL 30
#define KA_COUNT 3
#define USER_TIMEOUT 150

static void print_tlscert(const xmpp_tlscert_t *cert)
{
    const char *name;
    size_t n;
    for (n = 0; n < (unsigned)XMPP_CERT_ELEMENT_MAX; ++n) {
        printf("\t%32s: %s\n", xmpp_tlscert_get_description(n),
               xmpp_tlscert_get_string(cert, n));
    }
    n = 0;
    while ((name = xmpp_tlscert_get_dnsname(cert, n++)) != NULL)
        printf("\t%32s: %s\n", "dnsName", name);
    printf("PEM:\n%s\n", xmpp_tlscert_get_pem(cert));
}

/* define a handler for connection events */
static void conn_handler(xmpp_conn_t *conn,
                         xmpp_conn_event_t status,
                         int error,
                         xmpp_stream_error_t *stream_error,
                         void *userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    int secured;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: connected\n");
        secured = xmpp_conn_is_secured(conn);
        fprintf(stderr, "DEBUG: connection is %s.\n",
                secured ? "secured" : "NOT secured");
        if (secured) {
            xmpp_tlscert_t *cert = xmpp_conn_get_peer_cert(conn);
            print_tlscert(cert);
            xmpp_tlscert_free(cert);
        }
        xmpp_disconnect(conn);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

static int certfail_handler(const xmpp_tlscert_t *cert,
                            const char *const errormsg)
{
    char read_char[16] = {0};
    printf("Received certificate can't be validated!\n");
    printf("Reason: %s\n", errormsg);
    print_tlscert(cert);
    printf("Do you agree to connect?\n[y(es)|n(o)]: ");
    fflush(stdout);
    if (fgets(read_char, sizeof(read_char), stdin) == NULL) {
        printf("fgets() failed\n");
        return 0;
    }
    printf("\n");
    return read_char[0] == 'y' || read_char[0] == 'Y';
}

#ifdef _WIN32
static char *getpassword(const char *prompt, size_t maxlen)
{
    char *b, *buffer = malloc(maxlen);
    size_t i = 0;

    b = buffer;
    fputs(prompt, stderr);
    for (i = 0; i < maxlen; i++, b++) {
        char c = _getch();
        if (c == '\r' || c == '\n')
            break;
        *b = c;
    }
    *b = '\0';
    fputs("\n", stderr);
    return buffer;
}
#else
#define getpassword(prompt, maxlen) getpass(prompt)
#endif

static int
password_callback(char *pw, size_t pw_max, xmpp_conn_t *conn, void *userdata)
{
    (void)userdata;
    printf("Trying to unlock %s\n", xmpp_conn_get_keyfile(conn));
    char *pass = getpassword("Please enter password: ", pw_max);
    if (!pass)
        return -1;
    size_t passlen = strlen(pass);
    int ret;
    if (passlen >= pw_max) {
        ret = -1;
        goto out;
    }
    ret = passlen + 1;
    memcpy(pw, pass, ret);
out:
    memset(pass, 0, passlen);
    return ret;
}

static int sockopt_cb(xmpp_conn_t *conn, void *socket)
{
    int timeout = KA_TIMEOUT;
    int interval = KA_INTERVAL;
    int count = KA_COUNT;
    unsigned int user_timeout = USER_TIMEOUT;
    int ret;
    int optval = (timeout && interval) ? 1 : 0;

    (void)conn;

#ifdef _WIN32
    (void)count;
    (void)user_timeout;

    SOCKET sock = *((SOCKET *)socket);
    struct tcp_keepalive ka;
    DWORD dw = 0;

    ka.onoff = optval;
    ka.keepalivetime = timeout * 1000;
    ka.keepaliveinterval = interval * 1000;
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &dw,
                   NULL, NULL);
#else
    int sock = *((int *)socket);

    fprintf(stderr, "DEBUG: setting socket options\n");

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

static void usage(int exit_code)
{
    fprintf(stderr,
            "Usage: complex [options] [<host> [<port>]]\n\n"
            "Options:\n"
            "  --jid <jid>              The JID to use to authenticate.\n"
            "  --pass <pass>            The password of the JID.\n"
            "  --tls-cert <cert>        Path to client certificate.\n"
            "  --tls-key <key>          Path to private key or P12 file.\n\n"
            "  --capath <path>          Path to an additional CA trust store "
            "(directory).\n"
            "  --cafile <path>          Path to an additional CA trust store "
            "(single file).\n"
            "  --disable-tls            Disable TLS.\n"
            "  --mandatory-tls          Deny plaintext connection.\n"
            "  --trust-tls              Trust TLS certificate.\n"
            "  --enable-certfail        Enable certfail handler.\n"
            "  --legacy-ssl             Use old style SSL.\n"
            "  --legacy-auth            Allow legacy authentication.\n"
            "  --zlib                   Enable compression via zlib.\n"
            "  --dont-reset             When using zlib, don't do a full-flush "
            "after compression.\n"
            "  --verbose                Increase the verbosity level.\n"
            "  --tcp-keepalive          Configure TCP keepalive.\n\n"
            "Note: --disable-tls conflicts with --mandatory-tls or "
            "--legacy-ssl\n");

    exit(exit_code);
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *jid = NULL, *password = NULL, *cert = NULL, *key = NULL, *host = NULL,
         *capath = NULL, *cafile = NULL;
    long flags = 0;
    int tcp_keepalive = 0, verbosity = 0, certfail = 0;
    int i;
    unsigned long port = 0;

    /* take a jid and password on the command line */
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0)
            usage(0);
        else if (strcmp(argv[i], "--disable-tls") == 0)
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
        else if (strcmp(argv[i], "--mandatory-tls") == 0)
            flags |= XMPP_CONN_FLAG_MANDATORY_TLS;
        else if (strcmp(argv[i], "--trust-tls") == 0)
            flags |= XMPP_CONN_FLAG_TRUST_TLS;
        else if (strcmp(argv[i], "--legacy-ssl") == 0)
            flags |= XMPP_CONN_FLAG_LEGACY_SSL;
        else if (strcmp(argv[i], "--legacy-auth") == 0)
            flags |= XMPP_CONN_FLAG_LEGACY_AUTH;
        else if (strcmp(argv[i], "--zlib") == 0)
            flags |= XMPP_CONN_FLAG_ENABLE_COMPRESSION;
        else if (strcmp(argv[i], "--dont-reset") == 0)
            flags |= XMPP_CONN_FLAG_COMPRESSION_DONT_RESET;
        else if (strcmp(argv[i], "--verbose") == 0)
            verbosity++;
        else if (strcmp(argv[i], "--tcp-keepalive") == 0)
            tcp_keepalive = 1;
        else if (strcmp(argv[i], "--enable-certfail") == 0)
            certfail = 1;
        else if ((strcmp(argv[i], "--jid") == 0) && (++i < argc))
            jid = argv[i];
        else if ((strcmp(argv[i], "--pass") == 0) && (++i < argc))
            password = argv[i];
        else if ((strcmp(argv[i], "--tls-cert") == 0) && (++i < argc))
            cert = argv[i];
        else if ((strcmp(argv[i], "--tls-key") == 0) && (++i < argc))
            key = argv[i];
        else if ((strcmp(argv[i], "--capath") == 0) && (++i < argc))
            capath = argv[i];
        else if ((strcmp(argv[i], "--cafile") == 0) && (++i < argc))
            cafile = argv[i];
        else
            break;
    }
    if ((!jid && !key) || (argc - i) > 2) {
        usage(1);
    }

    if (i < argc)
        host = argv[i];
    if (i + 1 < argc)
        port = strtoul(argv[i + 1], NULL, 0);

    /*
     * Note, this example doesn't handle errors. Applications should check
     * return values of non-void functions.
     */

    /* init library */
    xmpp_initialize();

    /* pass NULL instead to silence output */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    /* create a context */
    ctx = xmpp_ctx_new(NULL, log);
    xmpp_ctx_set_verbosity(ctx, verbosity);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* configure connection properties (optional) */
    xmpp_conn_set_flags(conn, flags);
    /* configure TCP keepalive (optional) */
    if (tcp_keepalive)
        xmpp_conn_set_sockopt_callback(conn, sockopt_cb);

    /* ask for a password if key is protected */
    xmpp_conn_set_password_callback(conn, password_callback, NULL);
    /* try at max 3 times in case the user enters the password wrong */
    xmpp_conn_set_password_retries(conn, 3);
    /* setup authentication information */
    if (key) {
        xmpp_conn_set_client_cert(conn, cert, key);
    }
    if (jid)
        xmpp_conn_set_jid(conn, jid);
    if (password)
        xmpp_conn_set_pass(conn, password);

    if (certfail)
        xmpp_conn_set_certfail_handler(conn, certfail_handler);
    if (capath)
        xmpp_conn_set_capath(conn, capath);
    if (cafile)
        xmpp_conn_set_cafile(conn, cafile);

    /* initiate connection */
    if (xmpp_connect_client(conn, host, port, conn_handler, ctx) == XMPP_EOK) {

        /* enter the event loop -
           our connect handler will trigger an exit */
        xmpp_run(ctx);
    }

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();

    return 0;
}
