/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* resolver.c
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

#if !defined(_WIN32) && !defined(HAVE_CARES)
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif /* _WIN32 && HAVE_CARES */

#ifdef HAVE_CARES
#include <ares.h>
/* for select(2) */
#ifdef _WIN32
#include <winsock2.h>
#else /* _WIN32 */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* !_WIN32 */
#endif /* HAVE_CARES */

#include <string.h> /* strncpy */

#include "ostypes.h"
#include "snprintf.h"
#include "util.h" /* xmpp_min */
#include "resolver.h"

#define MESSAGE_HEADER_LEN 12
#define MESSAGE_RESPONSE 1
#define MESSAGE_T_SRV 33
#define MESSAGE_C_IN 1

/*******************************************************************************
 * Forward declarations.
 ******************************************************************************/

#ifdef HAVE_CARES
static int resolver_ares_srv_lookup_buf(xmpp_ctx_t *ctx,
                                        const unsigned char *buf,
                                        size_t len,
                                        resolver_srv_rr_t **srv_rr_list);
static int resolver_ares_srv_lookup(xmpp_ctx_t *ctx,
                                    const char *fulldomain,
                                    resolver_srv_rr_t **srv_rr_list);
#endif /* HAVE_CARES */

#ifndef HAVE_CARES
static int resolver_raw_srv_lookup_buf(xmpp_ctx_t *ctx,
                                       const unsigned char *buf,
                                       size_t len,
                                       resolver_srv_rr_t **srv_rr_list);
#endif /* !HAVE_CARES */

#if defined(_WIN32) && !defined(HAVE_CARES)
static int resolver_win32_srv_lookup(xmpp_ctx_t *ctx,
                                     const char *fulldomain,
                                     resolver_srv_rr_t **srv_rr_list);
static int resolver_win32_srv_query(const char *fulldomain,
                                    unsigned char *buf,
                                    size_t len);
#endif /* _WIN32 && !HAVE_CARES */

/*******************************************************************************
 * Implementation.
 ******************************************************************************/

void resolver_initialize(void)
{
#ifdef HAVE_CARES
    ares_library_init(ARES_LIB_INIT_ALL);
#endif
}

void resolver_shutdown(void)
{
#ifdef HAVE_CARES
    ares_library_cleanup();
#endif
}

resolver_srv_rr_t *resolver_srv_rr_new(xmpp_ctx_t *ctx,
                                       const char *host,
                                       unsigned short port,
                                       unsigned short prio,
                                       unsigned short weight)
{
    resolver_srv_rr_t *rr = strophe_alloc(ctx, sizeof(*rr));
    if (rr) {
        memset(rr, 0, sizeof(*rr));
        rr->port = port;
        rr->priority = prio;
        rr->weight = weight;
        if (host) {
            snprintf(rr->target, sizeof(rr->target), "%s", host);
        }
    }
    return rr;
}

static void resolver_srv_list_sort(resolver_srv_rr_t **srv_rr_list)
{
    resolver_srv_rr_t *rr_head;
    resolver_srv_rr_t *rr_current;
    resolver_srv_rr_t *rr_next;
    resolver_srv_rr_t *rr_prev;
    int swap;

    rr_head = *srv_rr_list;

    if ((rr_head == NULL) || (rr_head->next == NULL)) {
        /* Empty or single record list */
        return;
    }

    do {
        rr_prev = NULL;
        rr_current = rr_head;
        rr_next = rr_head->next;
        swap = 0;
        while (rr_next != NULL) {
            /*
             * RFC2052: A client MUST attempt to contact the target host
             * with the lowest-numbered priority it can reach.
             * RFC2052: When selecting a target host among the
             * those that have the same priority, the chance of trying
             * this one first SHOULD be proportional to its weight.
             */
            if ((rr_current->priority > rr_next->priority) ||
                (rr_current->priority == rr_next->priority &&
                 rr_current->weight < rr_next->weight)) {
                /* Swap node */
                swap = 1;
                if (rr_prev != NULL) {
                    rr_prev->next = rr_next;
                } else {
                    /* Swap head node */
                    rr_head = rr_next;
                }
                rr_current->next = rr_next->next;
                rr_next->next = rr_current;

                rr_prev = rr_next;
                rr_next = rr_current->next;
            } else {
                /* Next node */
                rr_prev = rr_current;
                rr_current = rr_next;
                rr_next = rr_next->next;
            }
        }
    } while (swap != 0);

    *srv_rr_list = rr_head;
}

int resolver_srv_lookup_buf(xmpp_ctx_t *ctx,
                            const unsigned char *buf,
                            size_t len,
                            resolver_srv_rr_t **srv_rr_list)
{
    int set;

#ifdef HAVE_CARES
    set = resolver_ares_srv_lookup_buf(ctx, buf, len, srv_rr_list);
#else
    set = resolver_raw_srv_lookup_buf(ctx, buf, len, srv_rr_list);
    if (set != XMPP_DOMAIN_FOUND && *srv_rr_list != NULL) {
        resolver_srv_free(ctx, *srv_rr_list);
        *srv_rr_list = NULL;
    }
#endif
    resolver_srv_list_sort(srv_rr_list);

    return set;
}

int resolver_srv_lookup(xmpp_ctx_t *ctx,
                        const char *service,
                        const char *proto,
                        const char *domain,
                        resolver_srv_rr_t **srv_rr_list)
{
#define RESOLVER_BUF_MAX 65536
    unsigned char *buf;
    char fulldomain[2048];
    int len;
    int set = XMPP_DOMAIN_NOT_FOUND;

    (void)buf;
    (void)len;

    strophe_snprintf(fulldomain, sizeof(fulldomain), "_%s._%s.%s", service,
                     proto, domain);

    *srv_rr_list = NULL;

#ifdef HAVE_CARES

    set = resolver_ares_srv_lookup(ctx, fulldomain, srv_rr_list);

#else /* HAVE_CARES */

#ifdef _WIN32
    set = resolver_win32_srv_lookup(ctx, fulldomain, srv_rr_list);
    if (set == XMPP_DOMAIN_FOUND)
        return set;
#endif /* _WIN32 */

    buf = strophe_alloc(ctx, RESOLVER_BUF_MAX);
    if (buf == NULL)
        return XMPP_DOMAIN_NOT_FOUND;

#ifdef _WIN32
    len = resolver_win32_srv_query(fulldomain, buf, RESOLVER_BUF_MAX);
#else  /* _WIN32 */
    len = res_query(fulldomain, MESSAGE_C_IN, MESSAGE_T_SRV, buf,
                    RESOLVER_BUF_MAX);
#endif /* _WIN32 */

    if (len > 0)
        set = resolver_srv_lookup_buf(ctx, buf, (size_t)len, srv_rr_list);

    strophe_free(ctx, buf);

#endif /* HAVE_CARES */

    return set;
}

void resolver_srv_free(xmpp_ctx_t *ctx, resolver_srv_rr_t *srv_rr_list)
{
    resolver_srv_rr_t *rr;

    while (srv_rr_list != NULL) {
        rr = srv_rr_list->next;
        strophe_free(ctx, srv_rr_list);
        srv_rr_list = rr;
    }
}

#ifndef HAVE_CARES
/*******************************************************************************
 * Resolver raw implementation.
 *
 * This code is common for both unix and win32.
 ******************************************************************************/

struct message_header {
    uint16_t id;
    uint8_t octet2;
    uint8_t octet3;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* the same as ntohs(), but receives pointer to the value */
static uint16_t xmpp_ntohs_ptr(const void *ptr)
{
    const uint8_t *p = (const uint8_t *)ptr;

    return (uint16_t)((p[0] << 8U) + p[1]);
}

static uint8_t message_header_qr(const struct message_header *header)
{
    return (header->octet2 >> 7) & 1;
}

static uint8_t message_header_rcode(const struct message_header *header)
{
    return header->octet3 & 0x0f;
}

/*
 * Append a label or a dot to the target name with buffer overflow checks.
 * Returns length of the non-truncated resulting string, may be bigger than
 * name_max.
 */
static size_t message_name_append_safe(char *name,
                                       size_t name_len,
                                       size_t name_max,
                                       const char *tail,
                                       size_t tail_len)
{
    size_t copy_len;

    copy_len = name_max > name_len ? name_max - name_len : 0;
    copy_len = xmpp_min(tail_len, copy_len);
    if (copy_len > 0)
        memcpy(&name[name_len], tail, copy_len);

    return name_len + tail_len;
}

/* Returns length of the compressed name. This is NOT the same as strlen(). */
static unsigned message_name_get(const unsigned char *buf,
                                 size_t buf_len,
                                 unsigned buf_offset,
                                 char *name,
                                 size_t name_max)
{
    size_t name_len = 0;
    unsigned i = buf_offset;
    unsigned pointer;
    unsigned rc;
    unsigned char label_len;

    while (1) {
        if (i >= buf_len)
            return 0;
        label_len = buf[i++];
        if (label_len == 0)
            break;

        /* Label */
        if ((label_len & 0xc0) == 0) {
            if (i + label_len - 1 >= buf_len)
                return 0;
            if (name != NULL) {
                name_len = message_name_append_safe(name, name_len, name_max,
                                                    (char *)&buf[i], label_len);
                name_len =
                    message_name_append_safe(name, name_len, name_max, ".", 1);
            }
            i += label_len;

            /* Pointer */
        } else if ((label_len & 0xc0) == 0xc0) {
            if (i >= buf_len)
                return 0;
            pointer = (label_len & 0x3f) << 8 | buf[i++];
            /* Prevent infinite looping */
            if (pointer >= buf_offset)
                return 0;
            if (name != NULL && name_len >= name_max && name_max > 0) {
                /* We have filled the name buffer. Don't pass it recursively. */
                name[name_max - 1] = '\0';
                name = NULL;
                name_max = 0;
            }
            rc = message_name_get(
                buf, buf_len, pointer, name != NULL ? &name[name_len] : NULL,
                name_max > name_len ? name_max - name_len : 0);
            if (rc == 0)
                return 0;
            /* Pointer is always the last. */
            break;

            /* The 10 and 01 combinations are reserved for future use. */
        } else {
            return 0;
        }
    }
    if (label_len == 0) {
        if (name_len == 0)
            name_len = 1;
        /*
         * At this point name_len is length of the resulting name,
         * including '\0'. This value can be exported to allocate buffer
         * of precise size.
         */
        if (name != NULL && name_max > 0) {
            /*
             * Overwrite leading '.' with a '\0'. If the resulting name is
             * bigger than name_max it is truncated.
             */
            name[xmpp_min(name_len, name_max) - 1] = '\0';
        }
    }

    return i - buf_offset;
}

static unsigned
message_name_len(const unsigned char *buf, size_t buf_len, unsigned buf_offset)
{
    return message_name_get(buf, buf_len, buf_offset, NULL, SIZE_MAX);
}

#define BUF_OVERFLOW_CHECK(ptr, len)                  \
    do {                                              \
        if ((ptr) >= (len)) {                         \
            if (*srv_rr_list != NULL)                 \
                resolver_srv_free(ctx, *srv_rr_list); \
            *srv_rr_list = NULL;                      \
            return XMPP_DOMAIN_NOT_FOUND;             \
        }                                             \
    } while (0)

static int resolver_raw_srv_lookup_buf(xmpp_ctx_t *ctx,
                                       const unsigned char *buf,
                                       size_t len,
                                       resolver_srv_rr_t **srv_rr_list)
{
    unsigned i;
    unsigned j;
    unsigned name_len;
    unsigned rdlength;
    uint16_t type;
    uint16_t class;
    struct message_header header;
    resolver_srv_rr_t *rr;

    *srv_rr_list = NULL;

    if (len < MESSAGE_HEADER_LEN)
        return XMPP_DOMAIN_NOT_FOUND;

    header.id = xmpp_ntohs_ptr(&buf[0]);
    header.octet2 = buf[2];
    header.octet3 = buf[3];
    header.qdcount = xmpp_ntohs_ptr(&buf[4]);
    header.ancount = xmpp_ntohs_ptr(&buf[6]);
    header.nscount = xmpp_ntohs_ptr(&buf[8]);
    header.arcount = xmpp_ntohs_ptr(&buf[10]);
    if (message_header_qr(&header) != MESSAGE_RESPONSE ||
        message_header_rcode(&header) != 0) {
        return XMPP_DOMAIN_NOT_FOUND;
    }
    j = MESSAGE_HEADER_LEN;

    /* skip question section */
    for (i = 0; i < header.qdcount; ++i) {
        BUF_OVERFLOW_CHECK(j, len);
        name_len = message_name_len(buf, len, j);
        /* error in name format */
        if (name_len == 0)
            return XMPP_DOMAIN_NOT_FOUND;
        j += name_len + 4;
    }

    for (i = 0; i < header.ancount; ++i) {
        BUF_OVERFLOW_CHECK(j, len);
        name_len = message_name_len(buf, len, j);
        /* error in name format */
        if (name_len == 0)
            return XMPP_DOMAIN_NOT_FOUND;
        j += name_len;
        BUF_OVERFLOW_CHECK(j + 16, len);
        type = xmpp_ntohs_ptr(&buf[j]);
        class = xmpp_ntohs_ptr(&buf[j + 2]);
        rdlength = xmpp_ntohs_ptr(&buf[j + 8]);
        j += 10;
        if (type == MESSAGE_T_SRV && class == MESSAGE_C_IN) {
            rr = resolver_srv_rr_new(ctx, NULL, 0, 0, 0);
            if (rr) {
                rr->next = *srv_rr_list;
                rr->priority = xmpp_ntohs_ptr(&buf[j]);
                rr->weight = xmpp_ntohs_ptr(&buf[j + 2]);
                rr->port = xmpp_ntohs_ptr(&buf[j + 4]);
                name_len = message_name_get(buf, len, j + 6, rr->target,
                                            sizeof(rr->target));
                if (name_len > 0)
                    *srv_rr_list = rr;
                else
                    strophe_free(ctx, rr); /* skip broken record */
            }
        }
        j += rdlength;
    }

    return *srv_rr_list != NULL ? XMPP_DOMAIN_FOUND : XMPP_DOMAIN_NOT_FOUND;
}

#endif /* !HAVE_CARES */

#ifdef HAVE_CARES
/*******************************************************************************
 * Resolver implementation using c-ares library.
 ******************************************************************************/

struct resolver_ares_ctx {
    xmpp_ctx_t *ctx;
    int result;
    resolver_srv_rr_t *srv_rr_list;
};

static int resolver_ares_srv_lookup_buf(xmpp_ctx_t *ctx,
                                        const unsigned char *buf,
                                        size_t len,
                                        resolver_srv_rr_t **srv_rr_list)
{
    struct ares_srv_reply *srv;
    struct ares_srv_reply *item;
    resolver_srv_rr_t *rr;
    int rc;

    *srv_rr_list = NULL;

    rc = ares_parse_srv_reply(buf, len, &srv);
    if (rc != ARES_SUCCESS)
        return XMPP_DOMAIN_NOT_FOUND;

    item = srv;
    while (item != NULL) {
        rr = strophe_alloc(ctx, sizeof(*rr));
        if (rr == NULL)
            break;
        rr->next = *srv_rr_list;
        rr->priority = item->priority;
        rr->weight = item->weight;
        rr->port = item->port;
        strncpy(rr->target, item->host, sizeof(rr->target) - 1);
        rr->target[sizeof(rr->target) - 1] = '\0';
        *srv_rr_list = rr;
        item = item->next;
    }
    ares_free_data(srv);

    return *srv_rr_list == NULL ? XMPP_DOMAIN_NOT_FOUND : XMPP_DOMAIN_FOUND;
}

static void ares_srv_lookup_callback(
    void *arg, int status, int timeouts, unsigned char *buf, int len)
{
    struct resolver_ares_ctx *actx = arg;

    (void)timeouts;

    if (status != ARES_SUCCESS)
        actx->result = XMPP_DOMAIN_NOT_FOUND;
    else
        actx->result = resolver_ares_srv_lookup_buf(actx->ctx, buf, len,
                                                    &actx->srv_rr_list);
}

static int resolver_ares_srv_lookup(xmpp_ctx_t *ctx,
                                    const char *fulldomain,
                                    resolver_srv_rr_t **srv_rr_list)
{
    struct resolver_ares_ctx actx;
    ares_channel chan;
    struct timeval tv;
    struct timeval *tvp;
    fd_set rfds;
    fd_set wfds;
    int nfds;
    int rc;

    actx.ctx = ctx;
    actx.result = XMPP_DOMAIN_NOT_FOUND;
    actx.srv_rr_list = NULL;

    rc = ares_init(&chan);
    if (rc == ARES_SUCCESS) {
        ares_query(chan, fulldomain, MESSAGE_C_IN, MESSAGE_T_SRV,
                   ares_srv_lookup_callback, &actx);
        while (1) {
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            nfds = ares_fds(chan, &rfds, &wfds);
            if (nfds == 0)
                break;
            tvp = ares_timeout(chan, NULL, &tv);
            select(nfds, &rfds, &wfds, NULL, tvp);
            ares_process(chan, &rfds, &wfds);
        }
        ares_destroy(chan);
    }

    *srv_rr_list = actx.srv_rr_list;
    return actx.result;
}

#endif /* HAVE_CARES */

#if defined(_WIN32) && !defined(HAVE_CARES)
/*******************************************************************************
 * Next part was copied from sock.c and contains old win32 code.
 *
 * The idea is to get raw response from a name server and pass it to
 * resolver_srv_lookup_buf(). In fact, resolver_win32_srv_query() replaces
 * the call of res_query().
 * Dnsapi code is moved to a separated function resolver_srv_win32_lookup() and
 * changed to meet new API.
 *
 * XXX If the code is compiled it should work like before.
 ******************************************************************************/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <iphlpapi.h>

struct dnsquery_header {
    unsigned short id;
    unsigned char qr;
    unsigned char opcode;
    unsigned char aa;
    unsigned char tc;
    unsigned char rd;
    unsigned char ra;
    unsigned char z;
    unsigned char rcode;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct dnsquery_question {
    char qname[1024];
    unsigned short qtype;
    unsigned short qclass;
};

static void netbuf_add_16bitnum(unsigned char *buf,
                                int buflen,
                                int *offset,
                                unsigned short num)
{
    unsigned char *start = buf + *offset;
    unsigned char *p = start;

    /* assuming big endian */
    *p++ = (num >> 8) & 0xff;
    *p++ = (num) & 0xff;

    *offset += 2;
}

static void
netbuf_add_domain_name(unsigned char *buf, int buflen, int *offset, char *name)
{
    unsigned char *start = buf + *offset;
    unsigned char *p = start;
    unsigned char *wordstart, *wordend;

    wordstart = (unsigned char *)name;

    while (*wordstart) {
        int len;
        wordend = wordstart;
        while (*wordend && *wordend != '.') {
            wordend++;
        }

        len = (int)(wordend - wordstart);

        if (len > 0x3F) {
            len = 0x3F;
        }

        *p++ = len;

        while (wordstart != wordend) {
            *p++ = *wordstart++;
        }

        if (*wordstart == '.') {
            wordstart++;
        }
    }

    *p++ = '\0';

    *offset += (int)(p - start);
}

static void netbuf_add_dnsquery_header(unsigned char *buf,
                                       int buflen,
                                       int *offset,
                                       struct dnsquery_header *header)
{
    unsigned char *p;

    netbuf_add_16bitnum(buf, buflen, offset, header->id);

    p = buf + *offset;
    *p++ = ((header->qr & 0x01) << 7) | ((header->opcode & 0x0F) << 3) |
           ((header->aa & 0x01) << 2) | ((header->tc & 0x01) << 1) |
           ((header->rd & 0x01));
    *p++ = ((header->ra & 0x01) << 7) | ((header->z & 0x07) << 4) |
           ((header->rcode & 0x0F));
    *offset += 2;

    netbuf_add_16bitnum(buf, buflen, offset, header->qdcount);
    netbuf_add_16bitnum(buf, buflen, offset, header->ancount);
    netbuf_add_16bitnum(buf, buflen, offset, header->nscount);
    netbuf_add_16bitnum(buf, buflen, offset, header->arcount);
}

static void netbuf_add_dnsquery_question(unsigned char *buf,
                                         int buflen,
                                         int *offset,
                                         struct dnsquery_question *question)
{
    netbuf_add_domain_name(buf, buflen, offset, question->qname);
    netbuf_add_16bitnum(buf, buflen, offset, question->qtype);
    netbuf_add_16bitnum(buf, buflen, offset, question->qclass);
}

static int resolver_win32_srv_lookup(xmpp_ctx_t *ctx,
                                     const char *fulldomain,
                                     resolver_srv_rr_t **srv_rr_list)
{
    resolver_srv_rr_t *rr;
    HINSTANCE hdnsapi = NULL;

    DNS_STATUS(WINAPI * pDnsQuery_A)
    (PCSTR, WORD, DWORD, PIP4_ARRAY, DNS_RECORDA **, PVOID *);
    void(WINAPI * pDnsRecordListFree)(DNS_RECORDA *, DNS_FREE_TYPE);

    if (hdnsapi = LoadLibrary("dnsapi.dll")) {
        pDnsQuery_A = (void *)GetProcAddress(hdnsapi, "DnsQuery_A");
        pDnsRecordListFree =
            (void *)GetProcAddress(hdnsapi, "DnsRecordListFree");

        if (pDnsQuery_A && pDnsRecordListFree) {
            DNS_RECORDA *dnsrecords = NULL;
            DNS_STATUS error;

            error = pDnsQuery_A(fulldomain, DNS_TYPE_SRV, DNS_QUERY_STANDARD,
                                NULL, &dnsrecords, NULL);

            if (error == 0) {
                DNS_RECORDA *current = dnsrecords;

                while (current) {
                    if (current->wType == DNS_TYPE_SRV) {
                        rr = strophe_alloc(ctx, sizeof(*rr));
                        if (rr == NULL)
                            break;
                        rr->next = *srv_rr_list;
                        rr->port = current->Data.Srv.wPort;
                        rr->priority = current->Data.Srv.wPriority;
                        rr->weight = current->Data.Srv.wWeight;
                        strophe_snprintf(rr->target, sizeof(rr->target), "%s",
                                         current->Data.Srv.pNameTarget);
                        *srv_rr_list = rr;
                    }
                    current = current->pNext;
                }
            }

            pDnsRecordListFree(dnsrecords, DnsFreeRecordList);
        }

        FreeLibrary(hdnsapi);
    }
    resolver_srv_list_sort(srv_rr_list);

    return *srv_rr_list != NULL ? XMPP_DOMAIN_FOUND : XMPP_DOMAIN_NOT_FOUND;
}

static int
resolver_win32_srv_query(const char *fulldomain, unsigned char *buf, size_t len)
{
    int set = 0;
    int insize = 0;

    /* if dnsapi didn't work/isn't there, try querying the dns server manually
     */
    if (!set) {
        struct dnsquery_header header;
        struct dnsquery_question question;
        int offset = 0;
        int addrlen;
        sock_t sock;
        struct sockaddr_in dnsaddr;
        char dnsserverips[16][256];
        int numdnsservers = 0;
        int j;

        /* Try getting the DNS server ips from GetNetworkParams() in iphlpapi
         * first */
        if (!numdnsservers) {
            HINSTANCE hiphlpapi = NULL;
            DWORD(WINAPI * pGetNetworkParams)(PFIXED_INFO, PULONG);

            if (hiphlpapi = LoadLibrary("Iphlpapi.dll")) {
                pGetNetworkParams =
                    (void *)GetProcAddress(hiphlpapi, "GetNetworkParams");

                if (pGetNetworkParams) {
                    FIXED_INFO *fi;
                    ULONG len;
                    DWORD error;
                    char buffer[65535];

                    len = 65535;
                    fi = (FIXED_INFO *)buffer;

                    if ((error = pGetNetworkParams(fi, &len)) ==
                        ERROR_SUCCESS) {
                        IP_ADDR_STRING *pias = &(fi->DnsServerList);

                        while (pias && numdnsservers < 16) {
                            strcpy(dnsserverips[numdnsservers++],
                                   pias->IpAddress.String);
                            pias = pias->Next;
                        }
                    }
                }
            }
            FreeLibrary(hiphlpapi);
        }

        /* Next, try getting the DNS server ips from the registry */
        if (!numdnsservers) {
            HKEY search;
            LONG error;

            error = RegOpenKeyEx(
                HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 0,
                KEY_READ, &search);

            if (error != ERROR_SUCCESS) {
                error = RegOpenKeyEx(
                    HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP", 0,
                    KEY_READ, &search);
            }

            if (error == ERROR_SUCCESS) {
                char name[512];
                DWORD len = 512;

                error = RegQueryValueEx(search, "NameServer", NULL, NULL,
                                        (LPBYTE)name, &len);

                if (error != ERROR_SUCCESS) {
                    error = RegQueryValueEx(search, "DhcpNameServer", NULL,
                                            NULL, (LPBYTE)name, &len);
                }

                if (error == ERROR_SUCCESS) {
                    char *parse = "0123456789.", *start, *end;
                    start = name;
                    end = name;
                    name[len] = '\0';

                    while (*start && numdnsservers < 16) {
                        while (strchr(parse, *end)) {
                            end++;
                        }

                        strncpy(dnsserverips[numdnsservers++], start,
                                end - start);

                        while (*end && !strchr(parse, *end)) {
                            end++;
                        }

                        start = end;
                    }
                }
            }

            RegCloseKey(search);
        }

        if (!numdnsservers) {
            HKEY searchlist;
            LONG error;

            error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                 "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\P"
                                 "arameters\\Interfaces",
                                 0, KEY_READ, &searchlist);

            if (error == ERROR_SUCCESS) {
                unsigned int i;
                DWORD numinterfaces = 0;

                RegQueryInfoKey(searchlist, NULL, NULL, NULL, &numinterfaces,
                                NULL, NULL, NULL, NULL, NULL, NULL, NULL);

                for (i = 0; i < numinterfaces; i++) {
                    char name[512];
                    DWORD len = 512;
                    HKEY searchentry;

                    RegEnumKeyEx(searchlist, i, (LPTSTR)name, &len, NULL, NULL,
                                 NULL, NULL);

                    if (RegOpenKeyEx(searchlist, name, 0, KEY_READ,
                                     &searchentry) == ERROR_SUCCESS) {
                        if (RegQueryValueEx(searchentry, "DhcpNameServer", NULL,
                                            NULL, (LPBYTE)name,
                                            &len) == ERROR_SUCCESS) {
                            char *parse = "0123456789.", *start, *end;
                            start = name;
                            end = name;
                            name[len] = '\0';

                            while (*start && numdnsservers < 16) {
                                while (strchr(parse, *end)) {
                                    end++;
                                }

                                strncpy(dnsserverips[numdnsservers++], start,
                                        end - start);

                                while (*end && !strchr(parse, *end)) {
                                    end++;
                                }

                                start = end;
                            }
                        } else if (RegQueryValueEx(searchentry, "NameServer",
                                                   NULL, NULL, (LPBYTE)name,
                                                   &len) == ERROR_SUCCESS) {
                            char *parse = "0123456789.", *start, *end;
                            start = name;
                            end = name;
                            name[len] = '\0';

                            while (*start && numdnsservers < 16) {
                                while (strchr(parse, *end)) {
                                    end++;
                                }

                                strncpy(dnsserverips[numdnsservers++], start,
                                        end - start);

                                while (*end && !strchr(parse, *end)) {
                                    end++;
                                }

                                start = end;
                            }
                        }
                        RegCloseKey(searchentry);
                    }
                }
                RegCloseKey(searchlist);
            }
        }

        /* If we have a DNS server, use it */
        if (numdnsservers) {
            ULONG nonblocking = 1;
            int i;

            memset(&header, 0, sizeof(header));
            header.id = 12345; /* FIXME: Get a better id here */
            header.rd = 1;
            header.qdcount = 1;

            netbuf_add_dnsquery_header(buf, (int)len, &offset, &header);

            memset(&question, 0, sizeof(question));
            strncpy(question.qname, fulldomain, 1024);
            question.qtype = MESSAGE_T_SRV; /* SRV */
            question.qclass = MESSAGE_C_IN; /* INTERNET! */

            netbuf_add_dnsquery_question(buf, (int)len, &offset, &question);

            insize = 0;
            for (i = 0; i < numdnsservers && insize <= 0; i++) {
                sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                ioctlsocket(sock, FIONBIO, &nonblocking);

                memset(&dnsaddr, 0, sizeof(dnsaddr));

                dnsaddr.sin_family = AF_INET;
                dnsaddr.sin_port = htons(53);
                dnsaddr.sin_addr.s_addr = inet_addr(dnsserverips[i]);

                addrlen = sizeof(dnsaddr);
                sendto(sock, (char *)buf, offset, 0,
                       (struct sockaddr *)&dnsaddr, addrlen);
                for (j = 0; j < 50; j++) {
                    insize = recvfrom(sock, (char *)buf, (int)len, 0,
                                      (struct sockaddr *)&dnsaddr, &addrlen);
                    if (insize == SOCKET_ERROR) {
                        if (sock_error(NULL) == WSAEWOULDBLOCK) {
                            Sleep(100);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                closesocket(sock);
            }
            set = insize > 0;
        }
    }

    return set ? insize : -1;
}

#endif /* _WIN32 && !HAVE_CARES */
