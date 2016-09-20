/* common.h
** strophe XMPP client library -- internal common structures
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
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
#include "rand.h"
#include "snprintf.h"

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

    xmpp_rand_t *rand;
    xmpp_loop_status_t loop_status;
    xmpp_connlist_t *connlist;
};


/* convenience functions for accessing the context */
void *xmpp_alloc(const xmpp_ctx_t * const ctx, const size_t size);
void *xmpp_realloc(const xmpp_ctx_t * const ctx, void *p, 
                   const size_t size);
char *xmpp_strdup(const xmpp_ctx_t * const ctx, const char * const s);

void xmpp_log(const xmpp_ctx_t * const ctx,
              const xmpp_log_level_t level,
              const char * const area,
              const char * const fmt,
              va_list ap);

/* wrappers for xmpp_log at specific levels */
void xmpp_error(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...);
void xmpp_warn(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...);
void xmpp_info(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...);
void xmpp_debug(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...);

/** connection **/

/* opaque connection object */
typedef enum {
    XMPP_STATE_DISCONNECTED,
    XMPP_STATE_CONNECTING,
    XMPP_STATE_CONNECTED
} xmpp_conn_state_t;

typedef struct _xmpp_send_queue_t xmpp_send_queue_t;
struct _xmpp_send_queue_t {
    char *data;
    size_t len;
    size_t written;

    xmpp_send_queue_t *next;
};

typedef struct _xmpp_handlist_t xmpp_handlist_t;
struct _xmpp_handlist_t {
    /* common members */
    int user_handler;
    void *handler;
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
    };
};

#define MAX_DOMAIN_LEN 256

#define SASL_MASK_PLAIN     (1 << 0)
#define SASL_MASK_DIGESTMD5 (1 << 1)
#define SASL_MASK_ANONYMOUS (1 << 2)
#define SASL_MASK_SCRAMSHA1 (1 << 3)

enum {
    XMPP_PORT_CLIENT = 5222,
    XMPP_PORT_CLIENT_LEGACY_SSL = 5223,
    XMPP_PORT_COMPONENT = 5347,
};

typedef void (*xmpp_open_handler)(xmpp_conn_t * const conn);

struct _xmpp_conn_t {
    unsigned int ref;
    xmpp_ctx_t *ctx;
    xmpp_conn_type_t type;
    int is_raw;

    xmpp_conn_state_t state;
    uint64_t timeout_stamp;
    int error;
    xmpp_stream_error_t *stream_error;

    sock_t sock;
    int ka_timeout; /* TCP keepalive timeout */
    int ka_interval; /* TCP keepalive interval */

    tls_t *tls;
    int tls_support;
    int tls_disabled;
    int tls_mandatory;
    int tls_legacy_ssl;
    int tls_failed; /* set when tls fails, so we don't try again */
    int sasl_support; /* if true, field is a bitfield of supported 
                         mechanisms */
    int secured; /* set when stream is secured with TLS */

    /* if server returns <bind/> or <session/> we must do them */
    int bind_required;
    int session_required;

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

    /* user handlers only get called after authentication */
    int authenticated;
    
    /* connection events handler */
    xmpp_conn_handler conn_handler;
    void *userdata;

    /* other handlers */
    xmpp_handlist_t *timed_handlers;
    hash_t *id_handlers;
    xmpp_handlist_t *handlers;
};

void conn_disconnect(xmpp_conn_t * const conn);
void conn_disconnect_clean(xmpp_conn_t * const conn);
void conn_established(xmpp_conn_t * const conn);
void conn_open_stream(xmpp_conn_t * const conn);
int conn_tls_start(xmpp_conn_t * const conn);
void conn_prepare_reset(xmpp_conn_t * const conn, xmpp_open_handler handler);
void conn_parser_reset(xmpp_conn_t * const conn);


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
void handler_fire_stanza(xmpp_conn_t * const conn,
                         xmpp_stanza_t * const stanza);
uint64_t handler_fire_timed(xmpp_ctx_t * const ctx);
void handler_reset_timed(xmpp_conn_t *conn, int user_only);
void handler_add_timed(xmpp_conn_t * const conn,
                       xmpp_timed_handler handler,
                       const unsigned long period,
                       void * const userdata);
void handler_add_id(xmpp_conn_t * const conn,
                    xmpp_handler handler,
                    const char * const id,
                    void * const userdata);
void handler_add(xmpp_conn_t * const conn,
                 xmpp_handler handler,
                 const char * const ns,
                 const char * const name,
                 const char * const type,
                 void * const userdata);

/* utility functions */
void disconnect_mem_error(xmpp_conn_t * const conn);

/* auth functions */
void auth_handle_open(xmpp_conn_t * const conn);
void auth_handle_component_open(xmpp_conn_t * const conn);
void auth_handle_open_raw(xmpp_conn_t * const conn);
void auth_handle_open_stub(xmpp_conn_t * const conn);

#endif /* __LIBSTROPHE_COMMON_H__ */
