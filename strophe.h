/* strophe.h
** strophe XMPP client library C API
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
**  This software is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Strophe public C API definitions.
 */

#ifndef __LIBSTROPHE_STROPHE_H__
#define __LIBSTROPHE_STROPHE_H__

#include <stddef.h> /* size_t */

#ifdef __cplusplus
extern "C" {
#endif

/* namespace defines */
/** @def XMPP_NS_CLIENT
 *  Namespace definition for 'jabber:client'.
 */
#define XMPP_NS_CLIENT "jabber:client"
/** @def XMPP_NS_COMPONENT
 *  Namespace definition for 'jabber:component:accept'.
 */
#define XMPP_NS_COMPONENT "jabber:component:accept"
/** @def XMPP_NS_STREAMS
 *  Namespace definition for 'http://etherx.jabber.org/streams'.
 */
#define XMPP_NS_STREAMS "http://etherx.jabber.org/streams"
/** @def XMPP_NS_STREAMS_IETF
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-streams'.
 */
#define XMPP_NS_STREAMS_IETF "urn:ietf:params:xml:ns:xmpp-streams"
/** @def XMPP_NS_STANZAS_IETF
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-stanzas'.
 */
#define XMPP_NS_STANZAS_IETF "urn:ietf:params:xml:ns:xmpp-stanzas"
/** @def XMPP_NS_TLS
 *  Namespace definition for 'url:ietf:params:xml:ns:xmpp-tls'.
 */
#define XMPP_NS_TLS "urn:ietf:params:xml:ns:xmpp-tls"
/** @def XMPP_NS_SASL
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-sasl'.
 */
#define XMPP_NS_SASL "urn:ietf:params:xml:ns:xmpp-sasl"
/** @def XMPP_NS_BIND
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-bind'.
 */
#define XMPP_NS_BIND "urn:ietf:params:xml:ns:xmpp-bind"
/** @def XMPP_NS_SESSION
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-session'.
 */
#define XMPP_NS_SESSION "urn:ietf:params:xml:ns:xmpp-session"
/** @def XMPP_NS_AUTH
 *  Namespace definition for 'jabber:iq:auth'.
 */
#define XMPP_NS_AUTH "jabber:iq:auth"
/** @def XMPP_NS_DISCO_INFO
 *  Namespace definition for 'http://jabber.org/protocol/disco#info'.
 */
#define XMPP_NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
/** @def XMPP_NS_DISCO_ITEMS
 *  Namespace definition for 'http://jabber.org/protocol/disco#items'.
 */
#define XMPP_NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
/** @def XMPP_NS_ROSTER
 *  Namespace definition for 'jabber:iq:roster'.
 */
#define XMPP_NS_ROSTER "jabber:iq:roster"
/** @def XMPP_NS_REGISTER
 *  Namespace definition for 'jabber:iq:register'.
 */
#define XMPP_NS_REGISTER "jabber:iq:register"
/** @def XMPP_NS_SM
 *  Namespace definition for Stream Management.
 */
#define XMPP_NS_SM "urn:xmpp:sm:3"

/* error defines */
/** @def XMPP_EOK
 *  Success error code.
 */
#define XMPP_EOK 0
/** @def XMPP_EMEM
 *  Memory related failure error code.
 *
 *  This is returned on allocation errors and signals that the host may
 *  be out of memory.
 */
#define XMPP_EMEM -1
/** @def XMPP_EINVOP
 *  Invalid operation error code.
 *
 *  This error code is returned when the operation was invalid and signals
 *  that the Strophe API is being used incorrectly.
 */
#define XMPP_EINVOP -2
/** @def XMPP_EINT
 *  Internal failure error code.
 */
#define XMPP_EINT -3

/* initialization and shutdown */
void xmpp_initialize(void);
void xmpp_shutdown(void);

/* version */
int xmpp_version_check(int major, int minor);

/* run-time contexts */

/* user-replaceable memory allocator */
typedef struct _xmpp_mem_t xmpp_mem_t;

/* user-replaceable log object */
typedef struct _xmpp_log_t xmpp_log_t;

/* opaque run time context containing the above hooks */
typedef struct _xmpp_ctx_t xmpp_ctx_t;

typedef struct _xmpp_tlscert_t xmpp_tlscert_t;

xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t *mem, const xmpp_log_t *log);
void xmpp_ctx_free(xmpp_ctx_t *ctx);

/* set the verbosity level of the ctx */
void xmpp_ctx_set_verbosity(xmpp_ctx_t *ctx, int level);

/* free some blocks returned by other APIs, for example the
   buffer you get from xmpp_stanza_to_text */
void xmpp_free(const xmpp_ctx_t *ctx, void *p);

struct _xmpp_mem_t {
    void *(*alloc)(size_t size, void *userdata);
    void (*free)(void *p, void *userdata);
    void *(*realloc)(void *p, size_t size, void *userdata);
    void *userdata;
};

typedef enum {
    XMPP_LEVEL_DEBUG,
    XMPP_LEVEL_INFO,
    XMPP_LEVEL_WARN,
    XMPP_LEVEL_ERROR
} xmpp_log_level_t;

typedef enum { XMPP_UNKNOWN, XMPP_CLIENT, XMPP_COMPONENT } xmpp_conn_type_t;

typedef void (*xmpp_log_handler)(void *userdata,
                                 xmpp_log_level_t level,
                                 const char *area,
                                 const char *msg);

struct _xmpp_log_t {
    xmpp_log_handler handler;
    void *userdata;
};

/* return a default logger filtering at a given level */
xmpp_log_t *xmpp_get_default_logger(xmpp_log_level_t level);

/* connection */

/* opaque connection object */
typedef struct _xmpp_conn_t xmpp_conn_t;
typedef struct _xmpp_stanza_t xmpp_stanza_t;
typedef struct _xmpp_sm_t xmpp_sm_state_t;

/* connection flags */
#define XMPP_CONN_FLAG_DISABLE_TLS (1UL << 0)
#define XMPP_CONN_FLAG_MANDATORY_TLS (1UL << 1)
#define XMPP_CONN_FLAG_LEGACY_SSL (1UL << 2)
/** @def XMPP_CONN_FLAG_TRUST_TLS
 *  Trust server's certificate even if it is invalid.
 */
#define XMPP_CONN_FLAG_TRUST_TLS (1UL << 3)
/** @def XMPP_CONN_FLAG_LEGACY_AUTH
 *  Enable legacy authentication support.
 */
#define XMPP_CONN_FLAG_LEGACY_AUTH (1UL << 4)
/** @def XMPP_CONN_FLAG_DISABLE_SM
 *  Disable Stream-Management XEP-0198.
 */
#define XMPP_CONN_FLAG_DISABLE_SM (1UL << 5)

/* connect callback */
typedef enum {
    XMPP_CONN_CONNECT,
    XMPP_CONN_RAW_CONNECT,
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

/** Certificate Elements
 *
 *  @ingroup TLS
 */
typedef enum {
    XMPP_CERT_VERSION,            /**< X.509 Version */
    XMPP_CERT_SERIALNUMBER,       /**< SerialNumber */
    XMPP_CERT_SUBJECT,            /**< Subject */
    XMPP_CERT_ISSUER,             /**< Issuer */
    XMPP_CERT_NOTBEFORE,          /**< Issued on */
    XMPP_CERT_NOTAFTER,           /**< Expires on */
    XMPP_CERT_KEYALG,             /**< Public Key Algorithm */
    XMPP_CERT_SIGALG,             /**< Certificate Signature Algorithm */
    XMPP_CERT_FINGERPRINT_SHA1,   /**< Fingerprint SHA-1 */
    XMPP_CERT_FINGERPRINT_SHA256, /**< Fingerprint SHA-256 */
    XMPP_CERT_ELEMENT_MAX         /**< Last element of the enum */
} xmpp_cert_element_t;

typedef struct {
    xmpp_error_type_t type;
    char *text;
    xmpp_stanza_t *stanza;
} xmpp_stream_error_t;

typedef void (*xmpp_conn_handler)(xmpp_conn_t *conn,
                                  xmpp_conn_event_t event,
                                  int error,
                                  xmpp_stream_error_t *stream_error,
                                  void *userdata);

/** The Handler function which will be called when the TLS stack can't
 *  verify the authenticity of a Certificate that gets presented by
 *  the server we're trying to connect to.
 *
 *  When this function is called and details of the `cert` have to be
 *  kept, please copy them yourself. The `cert` object will be free'd
 *  automatically when this function returns.
 *
 *  NB: `errormsg` is specific per certificate on OpenSSL and the same
 *      for all certificates on GnuTLS.
 *
 *  @param cert a Strophe certificate object
 *  @param errormsg The error that caused this.
 *
 *  @return 0 if the connection attempt should be terminated,
 *          1 if the connection should be established.
 *
 *  @ingroup TLS
 */
typedef int (*xmpp_certfail_handler)(const xmpp_tlscert_t *cert,
                                     const char *const errormsg);

/** The Handler function which will be called when the TLS stack can't
 *  decrypt a password protected key file.
 *
 *  When this callback is called it shall write a NULL-terminated
 *  string of maximum length `pw_max - 1` to `pw`.
 *
 *  This is currently only supported for GnuTLS and OpenSSL.
 *
 *  On 2022-02-02 the following maximum lengths are valid:
 *  ```
 *  include/gnutls/pkcs11.h: #define GNUTLS_PKCS11_MAX_PIN_LEN 256
 *  include/openssl/pem.h: #define PEM_BUFSIZE 1024
 *  ```
 *
 *  We expect the buffer to be NULL-terminated, therefore the usable lengths
 *  are:
 *
 *  * 255 for GnuTLS
 *  * 1023 for OpenSSL
 *
 *  Useful API's inside this callback are e.g.
 *
 *  \ref xmpp_conn_get_keyfile
 *
 *
 *  @param pw       The buffer where the password shall be stored.
 *  @param pw_max   The maximum length of the password.
 *  @param conn     The Strophe connection object this callback originates from.
 *  @param userdata The userdata pointer as supplied when setting this callback.
 *
 *  @return -1 on error, else the number of bytes written to `pw` w/o
 *           terminating NUL byte
 *
 *  @ingroup TLS
 */
typedef int (*xmpp_password_callback)(char *pw,
                                      size_t pw_max,
                                      xmpp_conn_t *conn,
                                      void *userdata);

/** The function which will be called when Strophe creates a new socket.
 *
 *  The `sock` argument is a pointer that is dependent on the architecture
 *  Strophe is compiled for.
 *
 *  For POSIX compatible systems usage shall be:
 *  ```
 *  int soc = *((int*)sock);
 *  ```
 *
 *  On Windows usage shall be:
 *  ```
 *  SOCKET soc = *((SOCKET*)sock);
 *  ```
 *
 *  This function will be called for each socket that is created.
 *
 *  `examples/bot.c` uses a libstrophe supplied callback function that sets
 *  basic keepalive parameters (`xmpp_sockopt_cb_keepalive()`).
 *
 *  `examples/complex.c` implements a custom function that could be useful
 *  for an application.
 *
 *  @param conn     The Strophe connection object this callback originates from.
 *  @param sock     A pointer to the underlying file descriptor.
 *
 *  @return 0 on success, -1 on error
 *
 *  @ingroup Connections
 */
typedef int (*xmpp_sockopt_callback)(xmpp_conn_t *conn, void *sock);

/* an example callback that sets basic keepalive parameters */
int xmpp_sockopt_cb_keepalive(xmpp_conn_t *conn, void *sock);

void xmpp_send_error(xmpp_conn_t *conn, xmpp_error_type_t type, char *text);
xmpp_conn_t *xmpp_conn_new(xmpp_ctx_t *ctx);
xmpp_conn_t *xmpp_conn_clone(xmpp_conn_t *conn);
int xmpp_conn_release(xmpp_conn_t *conn);

long xmpp_conn_get_flags(const xmpp_conn_t *conn);
int xmpp_conn_set_flags(xmpp_conn_t *conn, long flags);
const char *xmpp_conn_get_jid(const xmpp_conn_t *conn);
const char *xmpp_conn_get_bound_jid(const xmpp_conn_t *conn);
void xmpp_conn_set_jid(xmpp_conn_t *conn, const char *jid);
void xmpp_conn_set_cafile(xmpp_conn_t *const conn, const char *path);
void xmpp_conn_set_capath(xmpp_conn_t *const conn, const char *path);
void xmpp_conn_set_certfail_handler(xmpp_conn_t *const conn,
                                    xmpp_certfail_handler hndl);
xmpp_tlscert_t *xmpp_conn_get_peer_cert(xmpp_conn_t *const conn);
void xmpp_conn_set_password_callback(xmpp_conn_t *conn,
                                     xmpp_password_callback cb,
                                     void *userdata);
void xmpp_conn_set_password_retries(xmpp_conn_t *conn, unsigned int retries);
const char *xmpp_conn_get_keyfile(const xmpp_conn_t *conn);
void xmpp_conn_set_client_cert(xmpp_conn_t *conn,
                               const char *cert,
                               const char *key);
unsigned int xmpp_conn_cert_xmppaddr_num(xmpp_conn_t *conn);
char *xmpp_conn_cert_xmppaddr(xmpp_conn_t *conn, unsigned int n);
const char *xmpp_conn_get_pass(const xmpp_conn_t *conn);
void xmpp_conn_set_pass(xmpp_conn_t *conn, const char *pass);
xmpp_ctx_t *xmpp_conn_get_context(xmpp_conn_t *conn);
void xmpp_conn_disable_tls(xmpp_conn_t *conn);
int xmpp_conn_is_secured(xmpp_conn_t *conn);
void xmpp_conn_set_sockopt_callback(xmpp_conn_t *conn,
                                    xmpp_sockopt_callback callback);
int xmpp_conn_is_connecting(xmpp_conn_t *conn);
int xmpp_conn_is_connected(xmpp_conn_t *conn);
int xmpp_conn_is_disconnected(xmpp_conn_t *conn);
int xmpp_conn_send_queue_len(const xmpp_conn_t *conn);

typedef enum {
    XMPP_QUEUE_OLDEST = -1,
    XMPP_QUEUE_YOUNGEST = -2,
} xmpp_queue_element_t;
char *xmpp_conn_send_queue_drop_element(xmpp_conn_t *conn,
                                        xmpp_queue_element_t which);

xmpp_sm_state_t *xmpp_conn_get_sm_state(xmpp_conn_t *conn);
int xmpp_conn_set_sm_state(xmpp_conn_t *conn, xmpp_sm_state_t *sm_state);

void xmpp_free_sm_state(xmpp_sm_state_t *sm_state);

int xmpp_connect_client(xmpp_conn_t *conn,
                        const char *altdomain,
                        unsigned short altport,
                        xmpp_conn_handler callback,
                        void *userdata);

int xmpp_connect_component(xmpp_conn_t *conn,
                           const char *server,
                           unsigned short port,
                           xmpp_conn_handler callback,
                           void *userdata);

int xmpp_connect_raw(xmpp_conn_t *conn,
                     const char *altdomain,
                     unsigned short altport,
                     xmpp_conn_handler callback,
                     void *userdata);
int xmpp_conn_open_stream_default(xmpp_conn_t *conn);
int xmpp_conn_open_stream(xmpp_conn_t *conn,
                          char **attributes,
                          size_t attributes_len);
int xmpp_conn_tls_start(xmpp_conn_t *conn);

void xmpp_disconnect(xmpp_conn_t *conn);

void xmpp_send(xmpp_conn_t *conn, xmpp_stanza_t *stanza);

void xmpp_send_raw_string(xmpp_conn_t *conn, const char *fmt, ...);
void xmpp_send_raw(xmpp_conn_t *conn, const char *data, size_t len);

/* handlers */

/* if the handler returns false it is removed */
typedef int (*xmpp_timed_handler)(xmpp_conn_t *conn, void *userdata);

void xmpp_timed_handler_add(xmpp_conn_t *conn,
                            xmpp_timed_handler handler,
                            unsigned long period,
                            void *userdata);
void xmpp_timed_handler_delete(xmpp_conn_t *conn, xmpp_timed_handler handler);

/* if the handler returns false it is removed */
typedef int (*xmpp_global_timed_handler)(xmpp_ctx_t *ctx, void *userdata);

void xmpp_global_timed_handler_add(xmpp_ctx_t *ctx,
                                   xmpp_global_timed_handler handler,
                                   unsigned long period,
                                   void *userdata);
void xmpp_global_timed_handler_delete(xmpp_ctx_t *ctx,
                                      xmpp_global_timed_handler handler);

/* if the handler returns false it is removed */
typedef int (*xmpp_handler)(xmpp_conn_t *conn,
                            xmpp_stanza_t *stanza,
                            void *userdata);

void xmpp_handler_add(xmpp_conn_t *conn,
                      xmpp_handler handler,
                      const char *ns,
                      const char *name,
                      const char *type,
                      void *userdata);
void xmpp_handler_delete(xmpp_conn_t *conn, xmpp_handler handler);

void xmpp_id_handler_add(xmpp_conn_t *conn,
                         xmpp_handler handler,
                         const char *id,
                         void *userdata);
void xmpp_id_handler_delete(xmpp_conn_t *conn,
                            xmpp_handler handler,
                            const char *id);

/*
void xmpp_register_stanza_handler(conn, stanza, xmlns, type, handler)
*/

/* stanzas */

/* allocate and initialize a blank stanza */
xmpp_stanza_t *xmpp_stanza_new(xmpp_ctx_t *ctx);
xmpp_stanza_t *xmpp_stanza_new_from_string(xmpp_ctx_t *ctx, const char *str);

/* clone a stanza */
xmpp_stanza_t *xmpp_stanza_clone(xmpp_stanza_t *stanza);

/* copies a stanza and all children */
xmpp_stanza_t *xmpp_stanza_copy(const xmpp_stanza_t *stanza);

/* free a stanza object and it's contents */
int xmpp_stanza_release(xmpp_stanza_t *stanza);

xmpp_ctx_t *xmpp_stanza_get_context(const xmpp_stanza_t *stanza);

int xmpp_stanza_is_text(xmpp_stanza_t *stanza);
int xmpp_stanza_is_tag(xmpp_stanza_t *stanza);

/* marshall a stanza into text for transmission or display */
int xmpp_stanza_to_text(xmpp_stanza_t *stanza, char **buf, size_t *buflen);

xmpp_stanza_t *xmpp_stanza_get_children(xmpp_stanza_t *stanza);
xmpp_stanza_t *xmpp_stanza_get_child_by_name(xmpp_stanza_t *stanza,
                                             const char *name);
xmpp_stanza_t *xmpp_stanza_get_child_by_ns(xmpp_stanza_t *stanza,
                                           const char *ns);
xmpp_stanza_t *xmpp_stanza_get_child_by_name_and_ns(xmpp_stanza_t *stanza,
                                                    const char *name,
                                                    const char *ns);
/* helper macro for names with a namespace */
#define XMPP_STANZA_NAME_IN_NS(name, ns) name "[@ns='" ns "']"
xmpp_stanza_t *xmpp_stanza_get_child_by_path(xmpp_stanza_t *stanza, ...);
xmpp_stanza_t *xmpp_stanza_get_next(xmpp_stanza_t *stanza);
int xmpp_stanza_add_child(xmpp_stanza_t *stanza, xmpp_stanza_t *child);
int xmpp_stanza_add_child_ex(xmpp_stanza_t *stanza,
                             xmpp_stanza_t *child,
                             int do_clone);

const char *xmpp_stanza_get_attribute(xmpp_stanza_t *stanza, const char *name);
int xmpp_stanza_get_attribute_count(xmpp_stanza_t *stanza);
int xmpp_stanza_get_attributes(xmpp_stanza_t *stanza,
                               const char **attr,
                               int attrlen);
/* concatenate all child text nodes.  this function
 * returns a string that must be freed by the caller */
char *xmpp_stanza_get_text(xmpp_stanza_t *stanza);
const char *xmpp_stanza_get_text_ptr(xmpp_stanza_t *stanza);
const char *xmpp_stanza_get_name(xmpp_stanza_t *stanza);
/* set_attribute adds/replaces attributes */
int xmpp_stanza_set_attribute(xmpp_stanza_t *stanza,
                              const char *key,
                              const char *value);
int xmpp_stanza_set_name(xmpp_stanza_t *stanza, const char *name);
int xmpp_stanza_set_text(xmpp_stanza_t *stanza, const char *text);
int xmpp_stanza_set_text_with_size(xmpp_stanza_t *stanza,
                                   const char *text,
                                   size_t size);
int xmpp_stanza_del_attribute(xmpp_stanza_t *stanza, const char *name);

/* common stanza helpers */
const char *xmpp_stanza_get_ns(xmpp_stanza_t *stanza);
const char *xmpp_stanza_get_type(xmpp_stanza_t *stanza);
const char *xmpp_stanza_get_id(xmpp_stanza_t *stanza);
const char *xmpp_stanza_get_to(xmpp_stanza_t *stanza);
const char *xmpp_stanza_get_from(xmpp_stanza_t *stanza);
int xmpp_stanza_set_ns(xmpp_stanza_t *stanza, const char *ns);
int xmpp_stanza_set_id(xmpp_stanza_t *stanza, const char *id);
int xmpp_stanza_set_type(xmpp_stanza_t *stanza, const char *type);
int xmpp_stanza_set_to(xmpp_stanza_t *stanza, const char *to);
int xmpp_stanza_set_from(xmpp_stanza_t *stanza, const char *from);

/* allocate and initialize a stanza in reply to another */
xmpp_stanza_t *xmpp_stanza_reply(xmpp_stanza_t *stanza);
xmpp_stanza_t *xmpp_stanza_reply_error(xmpp_stanza_t *stanza,
                                       const char *error_type,
                                       const char *condition,
                                       const char *text);

/* stanza subclasses */
xmpp_stanza_t *xmpp_message_new(xmpp_ctx_t *ctx,
                                const char *type,
                                const char *to,
                                const char *id);
char *xmpp_message_get_body(xmpp_stanza_t *msg);
int xmpp_message_set_body(xmpp_stanza_t *msg, const char *text);

xmpp_stanza_t *xmpp_iq_new(xmpp_ctx_t *ctx, const char *type, const char *id);
xmpp_stanza_t *xmpp_presence_new(xmpp_ctx_t *ctx);
xmpp_stanza_t *
xmpp_error_new(xmpp_ctx_t *ctx, xmpp_error_type_t type, const char *text);

/* jid */

/* these return new strings that must be xmpp_free()'d */
char *xmpp_jid_new(xmpp_ctx_t *ctx,
                   const char *node,
                   const char *domain,
                   const char *resource);
char *xmpp_jid_bare(xmpp_ctx_t *ctx, const char *jid);
char *xmpp_jid_node(xmpp_ctx_t *ctx, const char *jid);
char *xmpp_jid_domain(xmpp_ctx_t *ctx, const char *jid);
char *xmpp_jid_resource(xmpp_ctx_t *ctx, const char *jid);

/* event loop */

void xmpp_run_once(xmpp_ctx_t *ctx, unsigned long timeout);
void xmpp_run(xmpp_ctx_t *ctx);
void xmpp_stop(xmpp_ctx_t *ctx);
void xmpp_ctx_set_timeout(xmpp_ctx_t *ctx, unsigned long timeout);

/* TLS certificates */

xmpp_ctx_t *xmpp_tlscert_get_ctx(const xmpp_tlscert_t *cert);
xmpp_conn_t *xmpp_tlscert_get_conn(const xmpp_tlscert_t *cert);
const char *xmpp_tlscert_get_pem(const xmpp_tlscert_t *cert);
const char *xmpp_tlscert_get_dnsname(const xmpp_tlscert_t *cert, size_t n);
const char *xmpp_tlscert_get_string(const xmpp_tlscert_t *cert,
                                    xmpp_cert_element_t elmnt);
const char *xmpp_tlscert_get_description(xmpp_cert_element_t elmnt);
void xmpp_tlscert_free(xmpp_tlscert_t *cert);

/* UUID */

char *xmpp_uuid_gen(xmpp_ctx_t *ctx);

/* SHA1 */

/** @def XMPP_SHA1_DIGEST_SIZE
 *  Size of the SHA1 message digest.
 */
#define XMPP_SHA1_DIGEST_SIZE 20

typedef struct _xmpp_sha1_t xmpp_sha1_t;

char *xmpp_sha1(xmpp_ctx_t *ctx, const unsigned char *data, size_t len);
void xmpp_sha1_digest(const unsigned char *data,
                      size_t len,
                      unsigned char *digest);

xmpp_sha1_t *xmpp_sha1_new(xmpp_ctx_t *ctx);
void xmpp_sha1_free(xmpp_sha1_t *sha1);
void xmpp_sha1_update(xmpp_sha1_t *sha1, const unsigned char *data, size_t len);
void xmpp_sha1_final(xmpp_sha1_t *sha1);
char *xmpp_sha1_to_string(xmpp_sha1_t *sha1, char *s, size_t slen);
char *xmpp_sha1_to_string_alloc(xmpp_sha1_t *sha1);
void xmpp_sha1_to_digest(xmpp_sha1_t *sha1, unsigned char *digest);

/* Base64 */

char *
xmpp_base64_encode(xmpp_ctx_t *ctx, const unsigned char *data, size_t len);
char *xmpp_base64_decode_str(xmpp_ctx_t *ctx, const char *base64, size_t len);
void xmpp_base64_decode_bin(xmpp_ctx_t *ctx,
                            const char *base64,
                            size_t len,
                            unsigned char **out,
                            size_t *outlen);

/* RNG */

typedef struct _xmpp_rand_t xmpp_rand_t;

/** Create new xmpp_rand_t object.
 *
 *  @param ctx A Strophe context object
 *
 *  @ingroup Random
 */
xmpp_rand_t *xmpp_rand_new(xmpp_ctx_t *ctx);

/** Destroy an xmpp_rand_t object.
 *
 *  @param ctx A Strophe context object
 *  @param rand A xmpp_rand_t object
 *
 *  @ingroup Random
 */
void xmpp_rand_free(xmpp_ctx_t *ctx, xmpp_rand_t *rand);

/** Generate random integer.
 *  Analogue of rand(3).
 *
 *  @ingroup Random
 */
int xmpp_rand(xmpp_rand_t *rand);

/** Generate random bytes.
 *  Generates len bytes and stores them to the output buffer.
 *
 *  @param rand A xmpp_rand_t object
 *  @param output A buffer where a len random bytes will be placed.
 *  @param len Number of bytes reserved for the output..
 *
 *  @ingroup Random
 */
void xmpp_rand_bytes(xmpp_rand_t *rand, unsigned char *output, size_t len);

/** Generate a nonce that is printable randomized string.
 *  This function doesn't allocate memory and doesn't fail.
 *
 *  @param rand A xmpp_rand_t object
 *  @param output A buffer where a NULL-terminated string will be placed.
 *                The string will contain len-1 printable symbols.
 *  @param len Number of bytes reserved for the output string, including
 *             end of line '\0'.
 *
 *  @ingroup Random
 */
void xmpp_rand_nonce(xmpp_rand_t *rand, char *output, size_t len);

/**
 * Formerly "private but exported" functions made public for now to announce
 * deprecation */
#include <stdarg.h>

#if defined(__GNUC__)
#if (__GNUC__ * 100 + __GNUC_MINOR__ >= 405)
#define XMPP_DEPRECATED(x) __attribute__((deprecated("replaced by " #x)))
#elif (__GNUC__ * 100 + __GNUC_MINOR__ >= 300)
#define XMPP_DEPRECATED(x) __attribute__((deprecated))
#endif
#elif defined(_MSC_VER) && _MSC_VER >= 1500
#define XMPP_DEPRECATED(x) __declspec(deprecated("replaced by " #x))
#else
#define XMPP_DEPRECATED(x)
#endif

XMPP_DEPRECATED(internal) void *xmpp_alloc(const xmpp_ctx_t *ctx, size_t size);
XMPP_DEPRECATED(internal)
void *xmpp_realloc(const xmpp_ctx_t *ctx, void *p, size_t size);
XMPP_DEPRECATED(internal)
char *xmpp_strdup(const xmpp_ctx_t *ctx, const char *s);
XMPP_DEPRECATED(internal)
char *xmpp_strndup(const xmpp_ctx_t *ctx, const char *s, size_t len);

XMPP_DEPRECATED(internal)
char *xmpp_strtok_r(char *s, const char *delim, char **saveptr);
XMPP_DEPRECATED(internal)
int xmpp_snprintf(char *str, size_t count, const char *fmt, ...);
XMPP_DEPRECATED(internal)
int xmpp_vsnprintf(char *str, size_t count, const char *fmt, va_list arg);

XMPP_DEPRECATED(internal)
void xmpp_log(const xmpp_ctx_t *ctx,
              xmpp_log_level_t level,
              const char *area,
              const char *fmt,
              va_list ap);
XMPP_DEPRECATED(internal)
void xmpp_error(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...);
XMPP_DEPRECATED(internal)
void xmpp_warn(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...);
XMPP_DEPRECATED(internal)
void xmpp_info(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...);
XMPP_DEPRECATED(internal)
void xmpp_debug(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...);
XMPP_DEPRECATED(internal)
void xmpp_debug_verbose(
    int level, const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...);

XMPP_DEPRECATED(xmpp_conn_set_sockopt_callback)
void xmpp_conn_set_keepalive(xmpp_conn_t *conn, int timeout, int interval);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSTROPHE_STROPHE_H__ */
