/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* common.h
** strophe XMPP client library -- internal common structures
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

/** @file
 *  Internally used functions and structures.
 */

#ifndef __LIBSTROPHE_COMMON_H__
#define __LIBSTROPHE_COMMON_H__

#include <stdio.h>
#include <stdarg.h>

#include "strophe.h"
#include "ostypes.h"
#include "sock.h"
#include "tls.h"
#include "hash.h"
#include "util.h"
#include "parser.h"
#include "snprintf.h"

/** Define your own `STROPHE_STATIC_ASSERT` if your compiler doesn't support one
 * of the below ones or define as noop if your compiler provides no replacement.
 */
#if !defined(STROPHE_STATIC_ASSERT)
#if (__STDC_VERSION__ >= 202000L)
#define STROPHE_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define STROPHE_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif
#endif

/** handlers **/
#if (__STDC_VERSION__ >= 202000L)
typedef void *xmpp_void_handler;
#else
typedef int (*xmpp_void_handler)();
#endif

typedef struct _xmpp_handlist_t xmpp_handlist_t;
struct _xmpp_handlist_t {
    /* common members */
    int user_handler;
    xmpp_void_handler handler;
    void *userdata;
    int enabled; /* handlers are added disabled and enabled after the
                  * handler chain is processed to prevent stanzas from
                  * getting processed by newly added handlers */
    xmpp_handlist_t *next;

    union {
        /* timed handlers */
        struct {
            unsigned long period;
            uint64_t last_stamp;
        };
        /* id handlers */
        struct {
            char *id;
        };
        /* normal handlers */
        struct {
            char *ns;
            char *name;
            char *type;
        };
    } u;
};

/** run-time context **/

typedef enum {
    XMPP_LOOP_NOTSTARTED,
    XMPP_LOOP_RUNNING,
    XMPP_LOOP_QUIT
} xmpp_loop_status_t;

typedef struct _xmpp_connlist_t {
    xmpp_conn_t *conn;
    struct _xmpp_connlist_t *next;
} xmpp_connlist_t;

struct _xmpp_ctx_t {
    const xmpp_mem_t *mem;
    const xmpp_log_t *log;
    int verbosity;

    xmpp_rand_t *rand;
    xmpp_loop_status_t loop_status;
    xmpp_connlist_t *connlist;
    xmpp_handlist_t *timed_handlers;

    unsigned long timeout;
};

/* convenience functions for accessing the context */
void *strophe_alloc(const xmpp_ctx_t *ctx, size_t size);
void *strophe_realloc(const xmpp_ctx_t *ctx, void *p, size_t size);
char *strophe_strdup(const xmpp_ctx_t *ctx, const char *s);
char *strophe_strndup(const xmpp_ctx_t *ctx, const char *s, size_t len);
void strophe_free(const xmpp_ctx_t *ctx, void *p);
#define strophe_free_and_null(ctx, p) \
    do {                              \
        if (p) {                      \
            strophe_free(ctx, (p));   \
            (p) = NULL;               \
        }                             \
    } while (0)

/* wrappers for xmpp_log at specific levels */
void strophe_error(const xmpp_ctx_t *ctx,
                   const char *area,
                   const char *fmt,
                   ...);
void strophe_warn(const xmpp_ctx_t *ctx,
                  const char *area,
                  const char *fmt,
                  ...);
void strophe_info(const xmpp_ctx_t *ctx,
                  const char *area,
                  const char *fmt,
                  ...);
void strophe_debug(const xmpp_ctx_t *ctx,
                   const char *area,
                   const char *fmt,
                   ...);
void strophe_debug_verbose(
    int level, const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...);

void strophe_log_internal(const xmpp_ctx_t *ctx,
                          xmpp_log_level_t level,
                          const char *area,
                          const char *fmt,
                          va_list ap);

#if defined(__OpenBSD__)
#define STR_MAYBE_NULL(p) (p) ? (p) : "(null)"
#else
#define STR_MAYBE_NULL(p) (p)
#endif

/** connection **/

/* opaque connection object */
typedef enum {
    XMPP_STATE_DISCONNECTED,
    XMPP_STATE_CONNECTING,
    XMPP_STATE_CONNECTED
} xmpp_conn_state_t;

typedef enum {
    XMPP_QUEUE_STROPHE = 0x1,
    XMPP_QUEUE_USER = 0x2,
    XMPP_QUEUE_SM = 0x800,
    XMPP_QUEUE_SM_STROPHE = XMPP_QUEUE_SM | XMPP_QUEUE_STROPHE,
} xmpp_send_queue_owner_t;

typedef struct _xmpp_send_queue_t xmpp_send_queue_t;
struct _xmpp_send_queue_t {
    char *data;
    size_t len;
    size_t written;
    int wip;
    xmpp_send_queue_owner_t owner;
    void *userdata;
    uint32_t sm_h;

    xmpp_send_queue_t *prev, *next;
};

#define UNUSED(x) ((void)(x))

#define MAX_DOMAIN_LEN 256

#define SASL_MASK_PLAIN (1 << 0)
#define SASL_MASK_DIGESTMD5 (1 << 1)
#define SASL_MASK_ANONYMOUS (1 << 2)
#define SASL_MASK_SCRAMSHA1 (1 << 3)
#define SASL_MASK_SCRAMSHA256 (1 << 4)
#define SASL_MASK_SCRAMSHA512 (1 << 5)
#define SASL_MASK_EXTERNAL (1 << 6)
#define SASL_MASK_SCRAMSHA1_PLUS (1 << 7)
#define SASL_MASK_SCRAMSHA256_PLUS (1 << 8)
#define SASL_MASK_SCRAMSHA512_PLUS (1 << 9)

#define SASL_MASK_SCRAM_PLUS                                 \
    (SASL_MASK_SCRAMSHA1_PLUS | SASL_MASK_SCRAMSHA256_PLUS | \
     SASL_MASK_SCRAMSHA512_PLUS)
#define SASL_MASK_SCRAM_WEAK \
    (SASL_MASK_SCRAMSHA1 | SASL_MASK_SCRAMSHA256 | SASL_MASK_SCRAMSHA512)
#define SASL_MASK_SCRAM (SASL_MASK_SCRAM_PLUS | SASL_MASK_SCRAM_WEAK)

enum {
    XMPP_PORT_CLIENT = 5222,
    XMPP_PORT_CLIENT_LEGACY_SSL = 5223,
    XMPP_PORT_COMPONENT = 5347,
};

typedef void (*xmpp_open_handler)(xmpp_conn_t *conn);

typedef struct {
    xmpp_send_queue_t *head, *tail;
} xmpp_queue_t;

struct _xmpp_sm_t {
    xmpp_ctx_t *ctx;
    int sm_support;
    int sm_enabled;
    int can_resume, resume, dont_request_resume;
    xmpp_queue_t sm_queue;
    int r_sent;
    uint32_t sm_handled_nr;
    uint32_t sm_sent_nr;
    char *id, *previd, *bound_jid;
    xmpp_stanza_t *bind;
};

struct conn_interface {
    int (*read)(struct conn_interface *intf, void *buff, size_t len);
    int (*write)(struct conn_interface *intf, const void *buff, size_t len);
    int (*flush)(struct conn_interface *intf);
    int (*pending)(struct conn_interface *intf);
    int (*get_error)(struct conn_interface *intf);
    int (*error_is_recoverable)(struct conn_interface *intf, int err);
    xmpp_conn_t *conn;
};

int conn_interface_write(struct conn_interface *intf,
                         const void *buff,
                         size_t len);
int conn_int_nop(struct conn_interface *intf);

int compression_init(xmpp_conn_t *conn);
void compression_free(xmpp_conn_t *conn);
void compression_handle_feature_children(xmpp_conn_t *conn, const char *text);

struct _xmpp_conn_t {
    struct conn_interface intf;

    unsigned int ref;
    xmpp_ctx_t *ctx;
    xmpp_conn_type_t type;
    int is_raw;

    xmpp_conn_state_t state;
    uint64_t timeout_stamp;
    int error;
    xmpp_stream_error_t *stream_error;

    xmpp_sock_t *xsock;
    sock_t sock;
    int ka_timeout;  /* TCP keepalive timeout */
    int ka_interval; /* TCP keepalive interval */
    int ka_count;    /* TCP keepalive count */

    tls_t *tls;
    int tls_support;
    int tls_disabled;
    int tls_mandatory;
    int tls_legacy_ssl;
    int tls_trust;
    char *tls_cafile;
    char *tls_capath;
    char *tls_client_cert;
    char *tls_client_key;
    int tls_failed;   /* set when tls fails, so we don't try again */
    int sasl_support; /* if true, field is a bitfield of supported
                         mechanisms */
    int auth_legacy_enabled;
    int secured; /* set when stream is secured with TLS */
    xmpp_certfail_handler certfail_handler;
    xmpp_password_callback password_callback;
    void *password_callback_userdata;
    struct {
        char pass[1024];
        unsigned char fname_hash[XMPP_SHA1_DIGEST_SIZE];
        size_t passlen, fnamelen;
    } password_cache;
    unsigned int password_retries;

    /* if server returns <bind/> or <session/> we must do them */
    int bind_required;
    int session_required;
    int sm_disable;
    xmpp_sm_state_t *sm_state;

    struct {
        struct xmpp_compression *state;
        int allowed, supported, dont_reset;
    } compression;

    char *lang;
    char *domain;
    char *jid;
    char *pass;
    char *bound_jid;
    char *stream_id;

    /* send queue and parameters */
    int blocking_send;
    int send_queue_max;
    int send_queue_len;
    int send_queue_user_len;
    xmpp_send_queue_t *send_queue_head;
    xmpp_send_queue_t *send_queue_tail;

    /* xml parser */
    int reset_parser;
    parser_t *parser;

    /* timeouts */
    unsigned int connect_timeout;

    /* event handlers */

    /* stream open handler */
    xmpp_open_handler open_handler;

    /* user handlers only get called after the stream negotiation has completed
     */
    int stream_negotiation_completed;

    /* connection events handler */
    xmpp_conn_handler conn_handler;
    void *userdata;

    /* other handlers */
    xmpp_handlist_t *timed_handlers;
    hash_t *id_handlers;
    xmpp_handlist_t *handlers;
    xmpp_sockopt_callback sockopt_cb;
    xmpp_sm_callback sm_callback;
    void *sm_callback_ctx;
};

void conn_disconnect(xmpp_conn_t *conn);
void conn_disconnect_clean(xmpp_conn_t *conn);
void conn_established(xmpp_conn_t *conn);
void conn_open_stream(xmpp_conn_t *conn);
int conn_tls_start(xmpp_conn_t *conn);
void conn_prepare_reset(xmpp_conn_t *conn, xmpp_open_handler handler);
void conn_parser_reset(xmpp_conn_t *conn);

typedef enum {
    XMPP_STANZA_UNKNOWN,
    XMPP_STANZA_TEXT,
    XMPP_STANZA_TAG
} xmpp_stanza_type_t;

struct _xmpp_stanza_t {
    int ref;
    xmpp_ctx_t *ctx;

    xmpp_stanza_type_t type;

    xmpp_stanza_t *prev;
    xmpp_stanza_t *next;
    xmpp_stanza_t *children;
    xmpp_stanza_t *parent;

    char *data;

    hash_t *attributes;
};

/* handler management */
void handler_fire_stanza(xmpp_conn_t *conn, xmpp_stanza_t *stanza);
uint64_t handler_fire_timed(xmpp_ctx_t *ctx);
void handler_reset_timed(xmpp_conn_t *conn, int user_only);
void handler_add_timed(xmpp_conn_t *conn,
                       xmpp_timed_handler handler,
                       unsigned long period,
                       void *userdata);
void handler_add_id(xmpp_conn_t *conn,
                    xmpp_handler handler,
                    const char *id,
                    void *userdata);
void handler_add(xmpp_conn_t *conn,
                 xmpp_handler handler,
                 const char *ns,
                 const char *name,
                 const char *type,
                 void *userdata);
void handler_system_delete_all(xmpp_conn_t *conn);

/* utility functions */
void trigger_sm_callback(xmpp_conn_t *conn);
void reset_sm_state(xmpp_sm_state_t *sm_state);
void disconnect_mem_error(xmpp_conn_t *conn);

/* auth functions */
void auth_handle_open(xmpp_conn_t *conn);
void auth_handle_component_open(xmpp_conn_t *conn);
void auth_handle_open_raw(xmpp_conn_t *conn);
void auth_handle_open_stub(xmpp_conn_t *conn);

/* queue functions */
void add_queue_back(xmpp_queue_t *queue, xmpp_send_queue_t *item);
xmpp_send_queue_t *peek_queue_front(xmpp_queue_t *queue);
xmpp_send_queue_t *pop_queue_front(xmpp_queue_t *queue);
char *queue_element_free(xmpp_ctx_t *ctx, xmpp_send_queue_t *e);

/* send functions */
void send_raw(xmpp_conn_t *conn,
              const char *data,
              size_t len,
              xmpp_send_queue_owner_t owner,
              void *userdata);
/* this is a bit special as it will always mark the sent string as
 * owned by libstrophe
 */
void send_raw_string(xmpp_conn_t *conn, const char *fmt, ...);
void send_stanza(xmpp_conn_t *conn,
                 xmpp_stanza_t *stanza,
                 xmpp_send_queue_owner_t owner);

#endif /* __LIBSTROPHE_COMMON_H__ */
