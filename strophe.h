/* strophe.h
** libstrophe XMPP client library API
**
** Copyright (C) 2005 OGG, LLC. All rights reserved.
*/

#ifndef __LIBSTROPHE_STROPHE_H__
#define __LIBSTROPHE_STROPHE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/* namespace defines */
#define XMPP_NS_CLIENT "jabber:client"
#define XMPP_NS_COMPONENT "jabber:component:accept"
#define XMPP_NS_STREAMS "http://etherx.jabber.org/streams"
#define XMPP_NS_TLS "urn:ietf:params:xml:ns:xmpp-tls"
#define XMPP_NS_SASL "urn:ietf:params:xml:ns:xmpp-sasl"
#define XMPP_NS_BIND "urn:ietf:params:xml:ns:xmpp-bind"
#define XMPP_NS_SESSION "urn:ietf:params:xml:ns:xmpp-session"
#define XMPP_NS_AUTH "jabber:iq:auth"
#define XMPP_NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define XMPP_NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define XMPP_NS_ROSTER "jabber:iq:roster"

/* error defines */
#define XMPP_EOK 0
#define XMPP_EMEM -1
#define XMPP_EINVOP -2
#define XMPP_EINT -3

/** initialization and shutdown **/

void xmpp_initialize(void);
void xmpp_shutdown(void);

/** version **/

int xmpp_version_check(int major, int minor);

/** run-time contexts **/

/* user-replaceable memory allocator */
typedef struct _xmpp_mem_t xmpp_mem_t;

/* user-replaceable log object */
typedef struct _xmpp_log_t xmpp_log_t;

/* opaque run time context containing the above hooks */
typedef struct _xmpp_ctx_t xmpp_ctx_t;

xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t * const mem, 
			     const xmpp_log_t * const log);
void xmpp_ctx_free(xmpp_ctx_t * const ctx);

struct _xmpp_mem_t {
    void *(*alloc)(const size_t size, void * const userdata);
    void (*free)(void *p, void * const userdata);
    void *(*realloc)(void *p, const size_t size, void * const userdata);
    void *userdata;
};

typedef enum {
    XMPP_LEVEL_DEBUG,
    XMPP_LEVEL_INFO,
    XMPP_LEVEL_WARN,
    XMPP_LEVEL_ERROR
} xmpp_log_level_t;

typedef enum {
    XMPP_UNKNOWN,
    XMPP_CLIENT,
    XMPP_COMPONENT
} xmpp_conn_type_t;

typedef void (*xmpp_log_handler)(void * const userdata, 
				 const xmpp_log_level_t level,
				 const char * const area,
				 const char * const msg);

struct _xmpp_log_t {
    xmpp_log_handler handler;
    void *userdata;
    /* mutex_t lock; */
};

/* return a default logger filtering at a given level */
xmpp_log_t *xmpp_get_default_logger(xmpp_log_level_t level);

/** connection **/

/* opaque connection object */
typedef struct _xmpp_conn_t xmpp_conn_t;
typedef struct _xmpp_stanza_t xmpp_stanza_t;

/* connect callback */
typedef enum {
    XMPP_CONN_CONNECT,
    XMPP_CONN_DISCONNECT,
    XMPP_CONN_FAIL
} xmpp_conn_event_t;

typedef enum {
    XMPP_SE_BAD_FORMAT,
    XMPP_SE_BAD_NS_PREFIX,
    XMPP_SE_CONFLICT,
    XMPP_SE_CONN_TIMEOUT,
    XMPP_SE_HOST_GONE,
    XMPP_SE_HOST_UNKNOWN,
    XMPP_SE_IMPROPER_ADDR,
    XMPP_SE_INTERNAL_SERVER_ERROR,
    XMPP_SE_INVALID_FROM,
    XMPP_SE_INVALID_ID,
    XMPP_SE_INVALID_NS,
    XMPP_SE_INVALID_XML,
    XMPP_SE_NOT_AUTHORIZED,
    XMPP_SE_POLICY_VIOLATION,
    XMPP_SE_REMOTE_CONN_FAILED,
    XMPP_SE_RESOURCE_CONSTRAINT,
    XMPP_SE_RESTRICTED_XML,
    XMPP_SE_SEE_OTHER_HOST,
    XMPP_SE_SYSTEM_SHUTDOWN,
    XMPP_SE_UNDEFINED_CONDITION,
    XMPP_SE_UNSUPPORTED_ENCODING,
    XMPP_SE_UNSUPPORTED_STANZA_TYPE,
    XMPP_SE_UNSUPPORTED_VERSION,
    XMPP_SE_XML_NOT_WELL_FORMED
} xmpp_error_type_t;

typedef struct {
    xmpp_error_type_t type;
    char *text;
    xmpp_stanza_t *stanza;
} xmpp_stream_error_t;

typedef void (*xmpp_conn_handler)(xmpp_conn_t * const conn, 
				  const xmpp_conn_event_t event,
				  const int error,
				  xmpp_stream_error_t * const stream_error,
				  void * const userdata);

xmpp_conn_t *xmpp_conn_new(xmpp_ctx_t * const ctx);
xmpp_conn_t * xmpp_conn_clone(xmpp_conn_t * const conn);
int xmpp_conn_release(xmpp_conn_t * const conn);

const char *xmpp_conn_get_jid(const xmpp_conn_t * const conn);
void xmpp_conn_set_jid(xmpp_conn_t * const conn, const char * const jid);
const char *xmpp_conn_get_pass(const xmpp_conn_t * const conn);
void xmpp_conn_set_pass(xmpp_conn_t * const conn, const char * const pass);

int xmpp_connect_client(xmpp_conn_t * const conn,
			const char * const domain,
			xmpp_conn_handler callback,
			void * const userdata);

/*
int xmpp_connect_component(conn, name)
*/
void xmpp_disconnect(xmpp_conn_t * const conn);

void xmpp_send(xmpp_conn_t * const conn,
	       xmpp_stanza_t * const stanza);


/* handlers */

/* if the handle returns false it is removed */
typedef int (*xmpp_timed_handler)(xmpp_conn_t * const conn, 
				  void * const userdata);

void xmpp_timed_handler_add(xmpp_conn_t * const conn,
			    xmpp_timed_handler handler,
			    const unsigned long period,
			    void * const userdata);
void xmpp_timed_handler_delete(xmpp_conn_t * const conn,
			       xmpp_timed_handler handler);


/* if the handler returns false it is removed */
typedef int (*xmpp_handler)(xmpp_conn_t * const conn,
			     xmpp_stanza_t * const stanza,
			     void * const userdata);

void xmpp_handler_add(xmpp_conn_t * const conn,
		      xmpp_handler handler,
		      const char * const ns,
		      const char * const name,
		      const char * const type,
		      void * const userdata);
void xmpp_handler_delete(xmpp_conn_t * const conn,
			 xmpp_handler handler);

void xmpp_id_handler_add(xmpp_conn_t * const conn,
			 xmpp_handler handler,
			 const char * const id,
			 void * const userdata);
void xmpp_id_handler_delete(xmpp_conn_t * const conn,
			    xmpp_handler handler,
			    const char * const id);

/*
void xmpp_register_stanza_handler(conn, stanza, xmlns, type, handler)
*/

/** stanzas **/

/** allocate an initialize a blank stanza */
xmpp_stanza_t *xmpp_stanza_new(xmpp_ctx_t *ctx);

/** clone a stanza */
xmpp_stanza_t *xmpp_stanza_clone(xmpp_stanza_t * const stanza);

/** copies a stanza and all children */
xmpp_stanza_t * xmpp_stanza_copy(const xmpp_stanza_t * const stanza);

/** free a stanza object and it's contents */
int xmpp_stanza_release(xmpp_stanza_t * const stanza);

/** marshall a stanza into text for transmission or display **/
int xmpp_stanza_to_text(xmpp_stanza_t *stanza, 
			char ** const buf, size_t * const buflen);

xmpp_stanza_t *xmpp_stanza_get_children(xmpp_stanza_t * const stanza);
xmpp_stanza_t *xmpp_stanza_get_child_by_name(xmpp_stanza_t * const stanza, 
					     const char * const name);
xmpp_stanza_t *xmpp_stanza_get_next(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_attribute(xmpp_stanza_t * const stanza,
				const char * const name);
char * xmpp_stanza_get_ns(xmpp_stanza_t * const stanza);
/* concatenate all child text nodes.  this function
 * returns a string that must be freed by the caller */
char *xmpp_stanza_get_text(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_name(xmpp_stanza_t * const stanza);

int xmpp_stanza_add_child(xmpp_stanza_t *stanza, xmpp_stanza_t *child);
int xmpp_stanza_set_ns(xmpp_stanza_t * const stanza, const char * const ns);
/* set_attribute adds/replaces attributes */
int xmpp_stanza_set_attribute(xmpp_stanza_t * const stanza, 
			      const char * const key,
			      const char * const value);
int xmpp_stanza_set_name(xmpp_stanza_t *stanza,
			 const char * const name);
int xmpp_stanza_set_text(xmpp_stanza_t *stanza,
			 const char * const text);
int xmpp_stanza_set_text_with_size(xmpp_stanza_t *stanza,
				   const char * const text, 
				   const size_t size);

/* common stanza helpers */
char *xmpp_stanza_get_type(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_id(xmpp_stanza_t * const stanza);
int xmpp_stanza_get_to();
int xmpp_stanza_get_from();
int xmpp_stanza_set_id(xmpp_stanza_t * const stanza, 
		       const char * const id);
int xmpp_stanza_set_type(xmpp_stanza_t * const stanza, 
			 const char * const type);
int xmpp_stanza_set_to();
int xmpp_stanza_set_from();

/** allocate and initialize a stanza in reply to another */
xmpp_stanza_t *xmpp_stanza_reply(const xmpp_stanza_t *stanza);

/* stanza subclasses */
void xmpp_message_new();
void xmpp_message_get_body();
void xmpp_message_set_body();

void xmpp_iq_new();
void xmpp_presence_new();


/** event loop **/
void xmpp_run_once(xmpp_ctx_t *ctx, const unsigned long  timeout);
void xmpp_run(xmpp_ctx_t *ctx);
void xmpp_stop(xmpp_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSTROPHE_STROPHE_H__ */
