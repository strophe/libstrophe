/* auth.c
** strophe XMPP client library -- auth functions and handlers
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Authentication function and handlers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "sasl.h"
#include "sha1.h"
#include "rand.h"

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

/* TODO: these should configurable at runtime on a per connection basis  */

#ifndef FEATURES_TIMEOUT
/** @def FEATURES_TIMEOUT
 *  Time to wait for &lt;stream:features/&gt; stanza.
 */
#define FEATURES_TIMEOUT 15000 /* 15 seconds */
#endif
#ifndef BIND_TIMEOUT
/** @def BIND_TIMEOUT
 *  Time to wait for &lt;bind/&gt; stanza reply.
 */
#define BIND_TIMEOUT 15000 /* 15 seconds */
#endif
#ifndef SESSION_TIMEOUT
/** @def SESSION_TIMEOUT
 *  Time to wait for &lt;session/&gt; stanza reply.
 */
#define SESSION_TIMEOUT 15000 /* 15 seconds */
#endif
#ifndef LEGACY_TIMEOUT
/** @def LEGACY_TIMEOUT
 *  Time to wait for legacy authentication to complete.
 */
#define LEGACY_TIMEOUT 15000 /* 15 seconds */
#endif
#ifndef HANDSHAKE_TIMEOUT
/** @def HANDSHAKE_TIMEOUT
 *  Time to wait for component authentication to complete
 */
#define HANDSHAKE_TIMEOUT 15000 /* 15 seconds */
#endif

static void _auth(xmpp_conn_t *conn);
static void _auth_legacy(xmpp_conn_t *conn);
static void _handle_open_sasl(xmpp_conn_t *conn);
static void _handle_open_tls(xmpp_conn_t *conn);

static int _handle_component_auth(xmpp_conn_t *conn);
static int _handle_component_hs_response(xmpp_conn_t *conn,
                                         xmpp_stanza_t *stanza,
                                         void *userdata);

static int
_handle_features_sasl(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata);
static int
_handle_sasl_result(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata);
static int _handle_digestmd5_challenge(xmpp_conn_t *conn,
                                       xmpp_stanza_t *stanza,
                                       void *userdata);
static int _handle_digestmd5_rspauth(xmpp_conn_t *conn,
                                     xmpp_stanza_t *stanza,
                                     void *userdata);
static int _handle_scram_challenge(xmpp_conn_t *conn,
                                   xmpp_stanza_t *stanza,
                                   void *userdata);
static char *_make_scram_init_msg(xmpp_conn_t *conn);

static int _handle_missing_features_sasl(xmpp_conn_t *conn, void *userdata);
static int _handle_missing_bind(xmpp_conn_t *conn, void *userdata);
static int
_handle_bind(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata);
static int
_handle_session(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata);
static int _handle_missing_session(xmpp_conn_t *conn, void *userdata);
static int _handle_missing_handshake(xmpp_conn_t *conn, void *userdata);

/* stream:error handler */
static int
_handle_error(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *child;
    const char *name;

    UNUSED(userdata);

    /* free old stream error if it's still there */
    if (conn->stream_error) {
        xmpp_stanza_release(conn->stream_error->stanza);
        if (conn->stream_error->text)
            xmpp_free(conn->ctx, conn->stream_error->text);
        xmpp_free(conn->ctx, conn->stream_error);
    }

    /* create stream error structure */
    conn->stream_error = (xmpp_stream_error_t *)xmpp_alloc(
        conn->ctx, sizeof(xmpp_stream_error_t));

    conn->stream_error->text = NULL;
    conn->stream_error->type = XMPP_SE_UNDEFINED_CONDITION;

    if (conn->stream_error) {
        child = xmpp_stanza_get_children(stanza);
        do {
            const char *ns = NULL;

            if (child) {
                ns = xmpp_stanza_get_ns(child);
            }

            if (ns && strcmp(ns, XMPP_NS_STREAMS_IETF) == 0) {
                name = xmpp_stanza_get_name(child);
                if (strcmp(name, "text") == 0) {
                    if (conn->stream_error->text)
                        xmpp_free(conn->ctx, conn->stream_error->text);
                    conn->stream_error->text = xmpp_stanza_get_text(child);
                } else if (strcmp(name, "bad-format") == 0)
                    conn->stream_error->type = XMPP_SE_BAD_FORMAT;
                else if (strcmp(name, "bad-namespace-prefix") == 0)
                    conn->stream_error->type = XMPP_SE_BAD_NS_PREFIX;
                else if (strcmp(name, "conflict") == 0)
                    conn->stream_error->type = XMPP_SE_CONFLICT;
                else if (strcmp(name, "connection-timeout") == 0)
                    conn->stream_error->type = XMPP_SE_CONN_TIMEOUT;
                else if (strcmp(name, "host-gone") == 0)
                    conn->stream_error->type = XMPP_SE_HOST_GONE;
                else if (strcmp(name, "host-unknown") == 0)
                    conn->stream_error->type = XMPP_SE_HOST_UNKNOWN;
                else if (strcmp(name, "improper-addressing") == 0)
                    conn->stream_error->type = XMPP_SE_IMPROPER_ADDR;
                else if (strcmp(name, "internal-server-error") == 0)
                    conn->stream_error->type = XMPP_SE_INTERNAL_SERVER_ERROR;
                else if (strcmp(name, "invalid-from") == 0)
                    conn->stream_error->type = XMPP_SE_INVALID_FROM;
                else if (strcmp(name, "invalid-id") == 0)
                    conn->stream_error->type = XMPP_SE_INVALID_ID;
                else if (strcmp(name, "invalid-namespace") == 0)
                    conn->stream_error->type = XMPP_SE_INVALID_NS;
                else if (strcmp(name, "invalid-xml") == 0)
                    conn->stream_error->type = XMPP_SE_INVALID_XML;
                else if (strcmp(name, "not-authorized") == 0)
                    conn->stream_error->type = XMPP_SE_NOT_AUTHORIZED;
                else if (strcmp(name, "policy-violation") == 0)
                    conn->stream_error->type = XMPP_SE_POLICY_VIOLATION;
                else if (strcmp(name, "remote-connection-failed") == 0)
                    conn->stream_error->type = XMPP_SE_REMOTE_CONN_FAILED;
                else if (strcmp(name, "resource-constraint") == 0)
                    conn->stream_error->type = XMPP_SE_RESOURCE_CONSTRAINT;
                else if (strcmp(name, "restricted-xml") == 0)
                    conn->stream_error->type = XMPP_SE_RESTRICTED_XML;
                else if (strcmp(name, "see-other-host") == 0)
                    conn->stream_error->type = XMPP_SE_SEE_OTHER_HOST;
                else if (strcmp(name, "system-shutdown") == 0)
                    conn->stream_error->type = XMPP_SE_SYSTEM_SHUTDOWN;
                else if (strcmp(name, "undefined-condition") == 0)
                    conn->stream_error->type = XMPP_SE_UNDEFINED_CONDITION;
                else if (strcmp(name, "unsupported-encoding") == 0)
                    conn->stream_error->type = XMPP_SE_UNSUPPORTED_ENCODING;
                else if (strcmp(name, "unsupported-stanza-type") == 0)
                    conn->stream_error->type = XMPP_SE_UNSUPPORTED_STANZA_TYPE;
                else if (strcmp(name, "unsupported-version") == 0)
                    conn->stream_error->type = XMPP_SE_UNSUPPORTED_VERSION;
                else if (strcmp(name, "xml-not-well-formed") == 0)
                    conn->stream_error->type = XMPP_SE_XML_NOT_WELL_FORMED;
            }
        } while ((child = xmpp_stanza_get_next(child)));

        conn->stream_error->stanza = xmpp_stanza_clone(stanza);
    }

    return 1;
}

/* stream:features handlers */
static int _handle_missing_features(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    xmpp_debug(conn->ctx, "xmpp", "didn't get stream features");

    /* legacy auth will be attempted */
    _auth(conn);

    return 0;
}

static int
_handle_features(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *child, *mech;
    const char *ns;
    char *text;

    UNUSED(userdata);

    /* remove the handler that detects missing stream:features */
    xmpp_timed_handler_delete(conn, _handle_missing_features);

    /* check for TLS */
    if (!conn->secured) {
        if (!conn->tls_disabled) {
            child = xmpp_stanza_get_child_by_name(stanza, "starttls");
            if (child) {
                ns = xmpp_stanza_get_ns(child);
                conn->tls_support = ns != NULL && strcmp(ns, XMPP_NS_TLS) == 0;
            }
        } else {
            conn->tls_support = 0;
        }
    }

    /* check for SASL */
    child = xmpp_stanza_get_child_by_name(stanza, "mechanisms");
    ns = child ? xmpp_stanza_get_ns(child) : NULL;
    if (child && ns && strcmp(ns, XMPP_NS_SASL) == 0) {
        for (mech = xmpp_stanza_get_children(child); mech;
             mech = xmpp_stanza_get_next(mech)) {
            if (xmpp_stanza_get_name(mech) &&
                strcmp(xmpp_stanza_get_name(mech), "mechanism") == 0) {
                text = xmpp_stanza_get_text(mech);
                if (text == NULL)
                    continue;

                if (strcasecmp(text, "PLAIN") == 0)
                    conn->sasl_support |= SASL_MASK_PLAIN;
                else if (strcasecmp(text, "EXTERNAL") == 0 &&
                         conn->tls_client_cert)
                    conn->sasl_support |= SASL_MASK_EXTERNAL;
                else if (strcasecmp(text, "DIGEST-MD5") == 0)
                    conn->sasl_support |= SASL_MASK_DIGESTMD5;
                else if (strcasecmp(text, "SCRAM-SHA-1") == 0)
                    conn->sasl_support |= SASL_MASK_SCRAMSHA1;
                else if (strcasecmp(text, "SCRAM-SHA-256") == 0)
                    conn->sasl_support |= SASL_MASK_SCRAMSHA256;
                else if (strcasecmp(text, "SCRAM-SHA-512") == 0)
                    conn->sasl_support |= SASL_MASK_SCRAMSHA512;
                else if (strcasecmp(text, "ANONYMOUS") == 0)
                    conn->sasl_support |= SASL_MASK_ANONYMOUS;

                xmpp_free(conn->ctx, text);
            }
        }
    }

    /* Disable PLAIN when other secure mechanisms are supported */
    if (conn->sasl_support & ~(SASL_MASK_PLAIN | SASL_MASK_ANONYMOUS))
        conn->sasl_support &= ~SASL_MASK_PLAIN;

    _auth(conn);

    return 0;
}

/* returns the correct auth id for a component or a client.
 * returned string must be freed by caller */
static char *_get_authid(xmpp_conn_t *conn)
{
    char *authid = NULL;

    if (conn->type == XMPP_CLIENT) {
        /* authid is the node portion of jid */
        if (!conn->jid)
            return NULL;
        authid = xmpp_jid_node(conn->ctx, conn->jid);
    }

    return authid;
}

static int _handle_proceedtls_default(xmpp_conn_t *conn,
                                      xmpp_stanza_t *stanza,
                                      void *userdata)
{
    const char *name;

    UNUSED(userdata);

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp", "handle proceedtls called for %s", name);

    if (strcmp(name, "proceed") == 0) {
        xmpp_debug(conn->ctx, "xmpp", "proceeding with TLS");

        if (conn_tls_start(conn) == 0) {
            conn_prepare_reset(conn, _handle_open_tls);
            conn_open_stream(conn);
        } else {
            /* failed tls spoils the connection, so disconnect */
            xmpp_disconnect(conn);
        }
    }

    return 0;
}

static int
_handle_sasl_result(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    const char *name;

    name = xmpp_stanza_get_name(stanza);

    /* the server should send a <success> or <failure> stanza */
    if (strcmp(name, "failure") == 0) {
        xmpp_debug(conn->ctx, "xmpp", "SASL %s auth failed", (char *)userdata);

        /* fall back to next auth method */
        _auth(conn);
    } else if (strcmp(name, "success") == 0) {
        /* SASL auth successful, we need to restart the stream */
        xmpp_debug(conn->ctx, "xmpp", "SASL %s auth successful",
                   (char *)userdata);

        /* reset parser */
        conn_prepare_reset(conn, _handle_open_sasl);

        /* send stream tag */
        conn_open_stream(conn);
    } else {
        /* got unexpected reply */
        xmpp_error(conn->ctx, "xmpp",
                   "Got unexpected reply to SASL %s authentication.",
                   (char *)userdata);
        xmpp_disconnect(conn);
    }

    return 0;
}

/* handle the challenge phase of digest auth */
static int _handle_digestmd5_challenge(xmpp_conn_t *conn,
                                       xmpp_stanza_t *stanza,
                                       void *userdata)
{
    char *text;
    char *response;
    xmpp_stanza_t *auth, *authdata;
    const char *name;

    UNUSED(userdata);

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp", "handle digest-md5 (challenge) called for %s",
               name);

    if (strcmp(name, "challenge") == 0) {
        text = xmpp_stanza_get_text(stanza);
        response = sasl_digest_md5(conn->ctx, text, conn->jid, conn->pass);
        if (!response) {
            disconnect_mem_error(conn);
            return 0;
        }
        xmpp_free(conn->ctx, text);

        auth = xmpp_stanza_new(conn->ctx);
        if (!auth) {
            disconnect_mem_error(conn);
            return 0;
        }
        xmpp_stanza_set_name(auth, "response");
        xmpp_stanza_set_ns(auth, XMPP_NS_SASL);

        authdata = xmpp_stanza_new(conn->ctx);
        if (!authdata) {
            disconnect_mem_error(conn);
            return 0;
        }

        xmpp_stanza_set_text(authdata, response);
        xmpp_free(conn->ctx, response);

        xmpp_stanza_add_child(auth, authdata);
        xmpp_stanza_release(authdata);

        handler_add(conn, _handle_digestmd5_rspauth, XMPP_NS_SASL, NULL, NULL,
                    NULL);

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

    } else {
        return _handle_sasl_result(conn, stanza, "DIGEST-MD5");
    }

    /* remove ourselves */
    return 0;
}

/* handle the rspauth phase of digest auth */
static int _handle_digestmd5_rspauth(xmpp_conn_t *conn,
                                     xmpp_stanza_t *stanza,
                                     void *userdata)
{
    xmpp_stanza_t *auth;
    const char *name;

    UNUSED(userdata);

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp", "handle digest-md5 (rspauth) called for %s",
               name);

    if (strcmp(name, "challenge") == 0) {
        /* assume it's an rspauth response */
        auth = xmpp_stanza_new(conn->ctx);
        if (!auth) {
            disconnect_mem_error(conn);
            return 0;
        }
        xmpp_stanza_set_name(auth, "response");
        xmpp_stanza_set_ns(auth, XMPP_NS_SASL);
        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);
    } else {
        return _handle_sasl_result(conn, stanza, "DIGEST-MD5");
    }

    return 1;
}

struct scram_user_data {
    char *scram_init;
    const struct hash_alg *alg;
};

/* handle the challenge phase of SCRAM-SHA-1 auth */
static int _handle_scram_challenge(xmpp_conn_t *conn,
                                   xmpp_stanza_t *stanza,
                                   void *userdata)
{
    char *text;
    char *response;
    xmpp_stanza_t *auth;
    xmpp_stanza_t *authdata;
    const char *name;
    char *challenge;
    struct scram_user_data *scram_ctx = (struct scram_user_data *)userdata;
    int rc;

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp", "handle %s (challenge) called for %s",
               scram_ctx->alg->scram_name, name);

    if (strcmp(name, "challenge") == 0) {
        text = xmpp_stanza_get_text(stanza);
        if (!text)
            goto err;

        challenge = xmpp_base64_decode_str(conn->ctx, text, strlen(text));
        xmpp_free(conn->ctx, text);
        if (!challenge)
            goto err;

        response = sasl_scram(conn->ctx, scram_ctx->alg, challenge,
                              scram_ctx->scram_init, conn->jid, conn->pass);
        xmpp_free(conn->ctx, challenge);
        if (!response)
            goto err;

        auth = xmpp_stanza_new(conn->ctx);
        if (!auth)
            goto err_free_response;
        xmpp_stanza_set_name(auth, "response");
        xmpp_stanza_set_ns(auth, XMPP_NS_SASL);

        authdata = xmpp_stanza_new(conn->ctx);
        if (!authdata)
            goto err_release_auth;
        xmpp_stanza_set_text(authdata, response);
        xmpp_free(conn->ctx, response);

        xmpp_stanza_add_child(auth, authdata);
        xmpp_stanza_release(authdata);

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        rc = 1; /* Keep handler */
    } else {
        /*
         * Free scram_ctx after calling _handle_sasl_result(). If authentication
         * fails, we want to try other mechanism which may be different SCRAM
         * mechanism. If we freed scram_ctx before the function, _auth() would
         * be able to allocate new scram_ctx object with the same address and
         * handler_add() would consider new SCRAM handler as duplicate, because
         * current handler is not removed yet. As result, libstrophe wouldn't
         * handle incoming challenge stanza.
         */
        rc = _handle_sasl_result(conn, stanza,
                                 (void *)scram_ctx->alg->scram_name);
        xmpp_free(conn->ctx, scram_ctx->scram_init);
        xmpp_free(conn->ctx, scram_ctx);
    }

    return rc;

err_release_auth:
    xmpp_stanza_release(auth);
err_free_response:
    xmpp_free(conn->ctx, response);
err:
    xmpp_free(conn->ctx, scram_ctx->scram_init);
    xmpp_free(conn->ctx, scram_ctx);
    disconnect_mem_error(conn);
    return 0;
}

static char *_make_scram_init_msg(xmpp_conn_t *conn)
{
    xmpp_ctx_t *ctx = conn->ctx;
    size_t message_len;
    char *node;
    char *message;
    char nonce[32];

    node = xmpp_jid_node(ctx, conn->jid);
    if (!node) {
        return NULL;
    }
    xmpp_rand_nonce(ctx->rand, nonce, sizeof(nonce));
    message_len = strlen(node) + strlen(nonce) + 8 + 1;
    message = xmpp_alloc(ctx, message_len);
    if (message) {
        xmpp_snprintf(message, message_len, "n,,n=%s,r=%s", node, nonce);
    }
    xmpp_free(ctx, node);

    return message;
}

static xmpp_stanza_t *_make_starttls(xmpp_conn_t *conn)
{
    xmpp_stanza_t *starttls;

    /* build start stanza */
    starttls = xmpp_stanza_new(conn->ctx);
    if (starttls) {
        xmpp_stanza_set_name(starttls, "starttls");
        xmpp_stanza_set_ns(starttls, XMPP_NS_TLS);
    }

    return starttls;
}

static xmpp_stanza_t *_make_sasl_auth(xmpp_conn_t *conn, const char *mechanism)
{
    xmpp_stanza_t *auth;

    /* build auth stanza */
    auth = xmpp_stanza_new(conn->ctx);
    if (auth) {
        xmpp_stanza_set_name(auth, "auth");
        xmpp_stanza_set_ns(auth, XMPP_NS_SASL);
        xmpp_stanza_set_attribute(auth, "mechanism", mechanism);
    }

    return auth;
}

/* authenticate the connection
 * this may get called multiple times.  if any auth method fails,
 * this will get called again until one auth method succeeds or every
 * method fails
 */
static void _auth(xmpp_conn_t *conn)
{
    xmpp_stanza_t *auth;
    xmpp_stanza_t *authdata;
    struct scram_user_data *scram_ctx;
    char *authid;
    char *str;
    int anonjid;

    /* if there is no node in conn->jid, we assume anonymous connect */
    str = xmpp_jid_node(conn->ctx, conn->jid);
    if (str == NULL) {
        anonjid = 1;
    } else {
        xmpp_free(conn->ctx, str);
        anonjid = 0;
    }

    if (conn->tls_support) {
        tls_t *tls = tls_new(conn);

        /* If we couldn't init tls, it isn't there, so go on */
        if (!tls) {
            conn->tls_support = 0;
            _auth(conn);
            return;
        } else {
            tls_free(tls);
        }

        auth = _make_starttls(conn);

        if (!auth) {
            disconnect_mem_error(conn);
            return;
        }

        handler_add(conn, _handle_proceedtls_default, XMPP_NS_TLS, NULL, NULL,
                    NULL);

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        /* TLS was tried, unset flag */
        conn->tls_support = 0;
        /* _auth() will be called later */
        return;
    }

    if (conn->tls_mandatory && !xmpp_conn_is_secured(conn)) {
        xmpp_error(conn->ctx, "xmpp",
                   "TLS is not supported, but set as "
                   "mandatory for this connection");
        conn_disconnect(conn);
        return;
    }

    if (anonjid && conn->sasl_support & SASL_MASK_ANONYMOUS) {
        /* some crap here */
        auth = _make_sasl_auth(conn, "ANONYMOUS");
        if (!auth) {
            disconnect_mem_error(conn);
            return;
        }

        handler_add(conn, _handle_sasl_result, XMPP_NS_SASL, NULL, NULL,
                    "ANONYMOUS");

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        /* SASL ANONYMOUS was tried, unset flag */
        conn->sasl_support &= ~SASL_MASK_ANONYMOUS;
    } else if (conn->sasl_support & SASL_MASK_EXTERNAL) {
        /* more crap here */
        auth = _make_sasl_auth(conn, "EXTERNAL");
        if (!auth) {
            disconnect_mem_error(conn);
            return;
        }

        authdata = xmpp_stanza_new(conn->ctx);
        if (!authdata) {
            xmpp_stanza_release(auth);
            disconnect_mem_error(conn);
            return;
        }
        str = tls_id_on_xmppaddr(conn, 0);
        if (!str || (tls_id_on_xmppaddr_num(conn) == 1 &&
                     strcmp(str, conn->jid) == 0)) {
            xmpp_stanza_set_text(authdata, "=");
        } else {
            xmpp_free(conn->ctx, str);
            str = xmpp_base64_encode(conn->ctx, (void *)conn->jid,
                                     strlen(conn->jid));
            if (!str) {
                xmpp_stanza_release(authdata);
                xmpp_stanza_release(auth);
                disconnect_mem_error(conn);
                return;
            }
            xmpp_stanza_set_text(authdata, str);
        }
        xmpp_free(conn->ctx, str);

        xmpp_stanza_add_child(auth, authdata);
        xmpp_stanza_release(authdata);

        handler_add(conn, _handle_sasl_result, XMPP_NS_SASL, NULL, NULL,
                    "EXTERNAL");

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        /* SASL EXTERNAL was tried, unset flag */
        conn->sasl_support &= ~SASL_MASK_EXTERNAL;
    } else if (anonjid) {
        xmpp_error(conn->ctx, "auth",
                   "No node in JID, and SASL ANONYMOUS unsupported.");
        xmpp_disconnect(conn);
    } else if (conn->pass == NULL) {
        xmpp_error(conn->ctx, "auth",
                   "Password hasn't been set, and SASL ANONYMOUS unsupported.");
        xmpp_disconnect(conn);
    } else if (conn->sasl_support & SASL_MASK_SCRAM) {
        scram_ctx = xmpp_alloc(conn->ctx, sizeof(*scram_ctx));
        if (conn->sasl_support & SASL_MASK_SCRAMSHA512)
            scram_ctx->alg = &scram_sha512;
        else if (conn->sasl_support & SASL_MASK_SCRAMSHA256)
            scram_ctx->alg = &scram_sha256;
        else if (conn->sasl_support & SASL_MASK_SCRAMSHA1)
            scram_ctx->alg = &scram_sha1;
        auth = _make_sasl_auth(conn, scram_ctx->alg->scram_name);
        if (!auth) {
            disconnect_mem_error(conn);
            return;
        }

        /* don't free scram_init on success */
        scram_ctx->scram_init = _make_scram_init_msg(conn);
        if (!scram_ctx->scram_init) {
            xmpp_free(conn->ctx, scram_ctx);
            xmpp_stanza_release(auth);
            disconnect_mem_error(conn);
            return;
        }

        str = xmpp_base64_encode(conn->ctx,
                                 (unsigned char *)scram_ctx->scram_init,
                                 strlen(scram_ctx->scram_init));
        if (!str) {
            xmpp_free(conn->ctx, scram_ctx->scram_init);
            xmpp_free(conn->ctx, scram_ctx);
            xmpp_stanza_release(auth);
            disconnect_mem_error(conn);
            return;
        }

        authdata = xmpp_stanza_new(conn->ctx);
        if (!authdata) {
            xmpp_free(conn->ctx, str);
            xmpp_free(conn->ctx, scram_ctx->scram_init);
            xmpp_free(conn->ctx, scram_ctx);
            xmpp_stanza_release(auth);
            disconnect_mem_error(conn);
            return;
        }
        xmpp_stanza_set_text(authdata, str);
        xmpp_free(conn->ctx, str);
        xmpp_stanza_add_child(auth, authdata);
        xmpp_stanza_release(authdata);

        handler_add(conn, _handle_scram_challenge, XMPP_NS_SASL, NULL, NULL,
                    (void *)scram_ctx);

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        /* SASL SCRAM-SHA-1 was tried, unset flag */
        conn->sasl_support &= ~scram_ctx->alg->mask;
    } else if (conn->sasl_support & SASL_MASK_DIGESTMD5) {
        auth = _make_sasl_auth(conn, "DIGEST-MD5");
        if (!auth) {
            disconnect_mem_error(conn);
            return;
        }

        handler_add(conn, _handle_digestmd5_challenge, XMPP_NS_SASL, NULL, NULL,
                    NULL);

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        /* SASL DIGEST-MD5 was tried, unset flag */
        conn->sasl_support &= ~SASL_MASK_DIGESTMD5;
    } else if (conn->sasl_support & SASL_MASK_PLAIN) {
        auth = _make_sasl_auth(conn, "PLAIN");
        if (!auth) {
            disconnect_mem_error(conn);
            return;
        }
        authdata = xmpp_stanza_new(conn->ctx);
        if (!authdata) {
            disconnect_mem_error(conn);
            return;
        }
        authid = _get_authid(conn);
        if (!authid) {
            disconnect_mem_error(conn);
            return;
        }
        str = sasl_plain(conn->ctx, authid, conn->pass);
        if (!str) {
            disconnect_mem_error(conn);
            return;
        }
        xmpp_stanza_set_text(authdata, str);
        xmpp_free(conn->ctx, str);
        xmpp_free(conn->ctx, authid);

        xmpp_stanza_add_child(auth, authdata);
        xmpp_stanza_release(authdata);

        handler_add(conn, _handle_sasl_result, XMPP_NS_SASL, NULL, NULL,
                    "PLAIN");

        xmpp_send(conn, auth);
        xmpp_stanza_release(auth);

        /* SASL PLAIN was tried */
        conn->sasl_support &= ~SASL_MASK_PLAIN;
    } else if (conn->type == XMPP_CLIENT && conn->auth_legacy_enabled) {
        /* legacy client authentication */
        _auth_legacy(conn);
    } else {
        xmpp_error(conn->ctx, "auth", "Cannot authenticate with known methods");
        xmpp_disconnect(conn);
    }
}

/** Set up handlers at stream start.
 *  This function is called internally to Strophe for handling the opening
 *  of an XMPP stream.  It's called by the parser when a stream is opened
 *  or reset, and adds the initial handlers for <stream:error/> and
 *  <stream:features/>.  This function is not intended for use outside
 *  of Strophe.
 *
 *  @param conn a Strophe connection object
 */
void auth_handle_open(xmpp_conn_t *conn)
{
    /* reset all timed handlers */
    handler_reset_timed(conn, 0);

    /* setup handler for stream:error, we will keep this handler
     * for reopened streams until connection is disconnected */
    handler_add(conn, _handle_error, XMPP_NS_STREAMS, "error", NULL, NULL);

    /* setup handlers for incoming <stream:features> */
    handler_add(conn, _handle_features, XMPP_NS_STREAMS, "features", NULL,
                NULL);
    handler_add_timed(conn, _handle_missing_features, FEATURES_TIMEOUT, NULL);
}

/* called when stream:stream tag received after TLS establishment */
static void _handle_open_tls(xmpp_conn_t *conn)
{
    /* setup handlers for incoming <stream:features> */
    handler_add(conn, _handle_features, XMPP_NS_STREAMS, "features", NULL,
                NULL);
    handler_add_timed(conn, _handle_missing_features, FEATURES_TIMEOUT, NULL);
}

/* called when stream:stream tag received after SASL auth */
static void _handle_open_sasl(xmpp_conn_t *conn)
{
    xmpp_debug(conn->ctx, "xmpp", "Reopened stream successfully.");

    /* setup stream:features handlers */
    handler_add(conn, _handle_features_sasl, XMPP_NS_STREAMS, "features", NULL,
                NULL);
    handler_add_timed(conn, _handle_missing_features_sasl, FEATURES_TIMEOUT,
                      NULL);
}

static int
_handle_features_sasl(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *bind, *session, *iq, *res, *text, *opt;
    const char *ns;
    char *resource;

    UNUSED(userdata);

    /* remove missing features handler */
    xmpp_timed_handler_delete(conn, _handle_missing_features_sasl);

    /* we are expecting <bind/> and <session/> since this is a
       XMPP style connection */

    /* check whether resource binding is required */
    bind = xmpp_stanza_get_child_by_name(stanza, "bind");
    if (bind) {
        ns = xmpp_stanza_get_ns(bind);
        conn->bind_required = ns != NULL && strcmp(ns, XMPP_NS_BIND) == 0;
    }

    /* check whether session establishment is required */
    session = xmpp_stanza_get_child_by_name(stanza, "session");
    if (session) {
        ns = xmpp_stanza_get_ns(session);
        opt = xmpp_stanza_get_child_by_name(session, "optional");
        if (!opt)
            conn->session_required =
                ns != NULL && strcmp(ns, XMPP_NS_SESSION) == 0;
    }

    /* if bind is required, go ahead and start it */
    if (conn->bind_required) {
        /* bind resource */

        /* setup response handlers */
        handler_add_id(conn, _handle_bind, "_xmpp_bind1", NULL);
        handler_add_timed(conn, _handle_missing_bind, BIND_TIMEOUT, NULL);

        /* send bind request */
        iq = xmpp_iq_new(conn->ctx, "set", "_xmpp_bind1");
        if (!iq) {
            disconnect_mem_error(conn);
            return 0;
        }

        bind = xmpp_stanza_copy(bind);
        if (!bind) {
            xmpp_stanza_release(iq);
            disconnect_mem_error(conn);
            return 0;
        }

        /* request a specific resource if we have one */
        resource = xmpp_jid_resource(conn->ctx, conn->jid);
        if ((resource != NULL) && (strlen(resource) == 0)) {
            /* jabberd2 doesn't handle an empty resource */
            xmpp_free(conn->ctx, resource);
            resource = NULL;
        }

        /* if we have a resource to request, do it. otherwise the
           server will assign us one */
        if (resource) {
            res = xmpp_stanza_new(conn->ctx);
            if (!res) {
                xmpp_stanza_release(bind);
                xmpp_stanza_release(iq);
                disconnect_mem_error(conn);
                return 0;
            }
            xmpp_stanza_set_name(res, "resource");
            text = xmpp_stanza_new(conn->ctx);
            if (!text) {
                xmpp_stanza_release(res);
                xmpp_stanza_release(bind);
                xmpp_stanza_release(iq);
                disconnect_mem_error(conn);
                return 0;
            }
            xmpp_stanza_set_text(text, resource);
            xmpp_stanza_add_child(res, text);
            xmpp_stanza_release(text);
            xmpp_stanza_add_child(bind, res);
            xmpp_stanza_release(res);
            xmpp_free(conn->ctx, resource);
        }

        xmpp_stanza_add_child(iq, bind);
        xmpp_stanza_release(bind);

        /* send bind request */
        xmpp_send(conn, iq);
        xmpp_stanza_release(iq);
    } else {
        /* can't bind, disconnect */
        xmpp_error(conn->ctx, "xmpp",
                   "Stream features does not allow "
                   "resource bind.");
        xmpp_disconnect(conn);
    }

    return 0;
}

static int _handle_missing_features_sasl(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    xmpp_error(conn->ctx, "xmpp",
               "Did not receive stream features "
               "after SASL authentication.");
    xmpp_disconnect(conn);
    return 0;
}

static int
_handle_bind(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    const char *type;
    xmpp_stanza_t *iq, *session;

    UNUSED(userdata);

    /* delete missing bind handler */
    xmpp_timed_handler_delete(conn, _handle_missing_bind);

    /* server has replied to bind request */
    type = xmpp_stanza_get_type(stanza);
    if (type && strcmp(type, "error") == 0) {
        xmpp_error(conn->ctx, "xmpp", "Binding failed.");
        xmpp_disconnect(conn);
    } else if (type && strcmp(type, "result") == 0) {
        xmpp_stanza_t *binding = xmpp_stanza_get_child_by_name(stanza, "bind");
        xmpp_debug(conn->ctx, "xmpp", "Bind successful.");

        if (binding) {
            xmpp_stanza_t *jid_stanza =
                xmpp_stanza_get_child_by_name(binding, "jid");
            if (jid_stanza) {
                conn->bound_jid = xmpp_stanza_get_text(jid_stanza);
            }
        }

        /* establish a session if required */
        if (conn->session_required) {
            /* setup response handlers */
            handler_add_id(conn, _handle_session, "_xmpp_session1", NULL);
            handler_add_timed(conn, _handle_missing_session, SESSION_TIMEOUT,
                              NULL);

            /* send session request */
            iq = xmpp_iq_new(conn->ctx, "set", "_xmpp_session1");
            if (!iq) {
                disconnect_mem_error(conn);
                return 0;
            }

            session = xmpp_stanza_new(conn->ctx);
            if (!session) {
                xmpp_stanza_release(iq);
                disconnect_mem_error(conn);
                return 0;
            }

            xmpp_stanza_set_name(session, "session");
            xmpp_stanza_set_ns(session, XMPP_NS_SESSION);

            xmpp_stanza_add_child(iq, session);
            xmpp_stanza_release(session);

            /* send session establishment request */
            xmpp_send(conn, iq);
            xmpp_stanza_release(iq);
        } else {
            conn->authenticated = 1;

            /* call connection handler */
            conn->conn_handler(conn, XMPP_CONN_CONNECT, 0, NULL,
                               conn->userdata);
        }
    } else {
        xmpp_error(conn->ctx, "xmpp", "Server sent malformed bind reply.");
        xmpp_disconnect(conn);
    }

    return 0;
}

static int _handle_missing_bind(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    xmpp_error(conn->ctx, "xmpp", "Server did not reply to bind request.");
    xmpp_disconnect(conn);
    return 0;
}

static int
_handle_session(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    const char *type;

    UNUSED(userdata);

    /* delete missing session handler */
    xmpp_timed_handler_delete(conn, _handle_missing_session);

    /* server has replied to the session request */
    type = xmpp_stanza_get_type(stanza);
    if (type && strcmp(type, "error") == 0) {
        xmpp_error(conn->ctx, "xmpp", "Session establishment failed.");
        xmpp_disconnect(conn);
    } else if (type && strcmp(type, "result") == 0) {
        xmpp_debug(conn->ctx, "xmpp", "Session establishment successful.");

        conn->authenticated = 1;

        /* call connection handler */
        conn->conn_handler(conn, XMPP_CONN_CONNECT, 0, NULL, conn->userdata);
    } else {
        xmpp_error(conn->ctx, "xmpp", "Server sent malformed session reply.");
        xmpp_disconnect(conn);
    }

    return 0;
}

static int _handle_missing_session(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    xmpp_error(conn->ctx, "xmpp", "Server did not reply to session request.");
    xmpp_disconnect(conn);
    return 0;
}

static int _handle_missing_legacy(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    xmpp_error(conn->ctx, "xmpp",
               "Server did not reply to legacy "
               "authentication request.");
    xmpp_disconnect(conn);
    return 0;
}

static int
_handle_legacy(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    const char *type;
    const char *name;

    UNUSED(userdata);

    /* delete missing handler */
    xmpp_timed_handler_delete(conn, _handle_missing_legacy);

    /* server responded to legacy auth request */
    type = xmpp_stanza_get_type(stanza);
    name = xmpp_stanza_get_name(stanza);
    if (!type || strcmp(name, "iq") != 0) {
        xmpp_error(conn->ctx, "xmpp",
                   "Server sent us an unexpected response "
                   "to legacy authentication request.");
        xmpp_disconnect(conn);
    } else if (strcmp(type, "error") == 0) {
        /* legacy client auth failed, no more fallbacks */
        xmpp_error(conn->ctx, "xmpp", "Legacy client authentication failed.");
        xmpp_disconnect(conn);
    } else if (strcmp(type, "result") == 0) {
        /* auth succeeded */
        xmpp_debug(conn->ctx, "xmpp", "Legacy auth succeeded.");

        conn->authenticated = 1;
        conn->conn_handler(conn, XMPP_CONN_CONNECT, 0, NULL, conn->userdata);
    } else {
        xmpp_error(conn->ctx, "xmpp",
                   "Server sent us a legacy authentication "
                   "response with a bad type.");
        xmpp_disconnect(conn);
    }

    return 0;
}

static void _auth_legacy(xmpp_conn_t *conn)
{
    xmpp_stanza_t *iq;
    xmpp_stanza_t *authdata;
    xmpp_stanza_t *query;
    xmpp_stanza_t *child;
    char *str;

    xmpp_debug(conn->ctx, "auth", "Legacy authentication request");

    iq = xmpp_iq_new(conn->ctx, "set", "_xmpp_auth1");
    if (!iq)
        goto err;

    query = xmpp_stanza_new(conn->ctx);
    if (!query)
        goto err_free;
    xmpp_stanza_set_name(query, "query");
    xmpp_stanza_set_ns(query, XMPP_NS_AUTH);
    xmpp_stanza_add_child(iq, query);
    xmpp_stanza_release(query);

    child = xmpp_stanza_new(conn->ctx);
    if (!child)
        goto err_free;
    xmpp_stanza_set_name(child, "username");
    xmpp_stanza_add_child(query, child);
    xmpp_stanza_release(child);

    authdata = xmpp_stanza_new(conn->ctx);
    if (!authdata)
        goto err_free;
    str = xmpp_jid_node(conn->ctx, conn->jid);
    if (!str) {
        xmpp_stanza_release(authdata);
        goto err_free;
    }
    xmpp_stanza_set_text(authdata, str);
    xmpp_free(conn->ctx, str);
    xmpp_stanza_add_child(child, authdata);
    xmpp_stanza_release(authdata);

    child = xmpp_stanza_new(conn->ctx);
    if (!child)
        goto err_free;
    xmpp_stanza_set_name(child, "password");
    xmpp_stanza_add_child(query, child);
    xmpp_stanza_release(child);

    authdata = xmpp_stanza_new(conn->ctx);
    if (!authdata)
        goto err_free;
    xmpp_stanza_set_text(authdata, conn->pass);
    xmpp_stanza_add_child(child, authdata);
    xmpp_stanza_release(authdata);

    child = xmpp_stanza_new(conn->ctx);
    if (!child)
        goto err_free;
    xmpp_stanza_set_name(child, "resource");
    xmpp_stanza_add_child(query, child);
    xmpp_stanza_release(child);

    authdata = xmpp_stanza_new(conn->ctx);
    if (!authdata)
        goto err_free;
    str = xmpp_jid_resource(conn->ctx, conn->jid);
    if (str) {
        xmpp_stanza_set_text(authdata, str);
        xmpp_free(conn->ctx, str);
    } else {
        xmpp_stanza_release(authdata);
        xmpp_stanza_release(iq);
        xmpp_error(conn->ctx, "auth", "Cannot authenticate without resource");
        xmpp_disconnect(conn);
        return;
    }
    xmpp_stanza_add_child(child, authdata);
    xmpp_stanza_release(authdata);

    handler_add_id(conn, _handle_legacy, "_xmpp_auth1", NULL);
    handler_add_timed(conn, _handle_missing_legacy, LEGACY_TIMEOUT, NULL);

    xmpp_send(conn, iq);
    xmpp_stanza_release(iq);
    return;

err_free:
    xmpp_stanza_release(iq);
err:
    disconnect_mem_error(conn);
}

void auth_handle_component_open(xmpp_conn_t *conn)
{
    int rc;

    /* reset all timed handlers */
    handler_reset_timed(conn, 0);

    handler_add(conn, _handle_error, XMPP_NS_STREAMS, "error", NULL, NULL);
    handler_add(conn, _handle_component_hs_response, NULL, "handshake", NULL,
                NULL);
    handler_add_timed(conn, _handle_missing_handshake, HANDSHAKE_TIMEOUT, NULL);

    rc = _handle_component_auth(conn);
    if (rc != 0) {
        xmpp_error(conn->ctx, "auth", "Component authentication failed.");
        xmpp_disconnect(conn);
    }
}

/* Will compute SHA1 and authenticate the component to the server */
int _handle_component_auth(xmpp_conn_t *conn)
{
    uint8_t md_value[SHA1_DIGEST_SIZE];
    SHA1_CTX mdctx;
    char *digest;
    size_t i;

    if (conn->stream_id == NULL) {
        xmpp_error(conn->ctx, "auth", "Received no stream id from the server.");
        return XMPP_EINT;
    }

    /* Feed the session id and passphrase to the algorithm.
     * We need to compute SHA1(session_id + passphrase)
     */
    crypto_SHA1_Init(&mdctx);
    crypto_SHA1_Update(&mdctx, (uint8_t *)conn->stream_id,
                       strlen(conn->stream_id));
    crypto_SHA1_Update(&mdctx, (uint8_t *)conn->pass, strlen(conn->pass));
    crypto_SHA1_Final(&mdctx, md_value);

    digest = xmpp_alloc(conn->ctx, 2 * sizeof(md_value) + 1);
    if (digest) {
        /* convert the digest into string representation */
        for (i = 0; i < sizeof(md_value); i++)
            xmpp_snprintf(digest + i * 2, 3, "%02x", md_value[i]);
        digest[2 * sizeof(md_value)] = '\0';

        xmpp_debug(conn->ctx, "auth", "Digest: %s, len: %d", digest,
                   strlen(digest));

        /* Send the digest to the server */
        xmpp_send_raw_string(conn, "<handshake xmlns='%s'>%s</handshake>",
                             XMPP_NS_COMPONENT, digest);
        xmpp_debug(conn->ctx, "auth",
                   "Sent component handshake to the server.");
        xmpp_free(conn->ctx, digest);
    } else {
        xmpp_debug(conn->ctx, "auth",
                   "Couldn't allocate memory for component "
                   "handshake digest.");
        return XMPP_EMEM;
    }

    return 0;
}

/* Check if the received stanza is <handshake/> and set auth to true
 * and fire connection handler.
 */
int _handle_component_hs_response(xmpp_conn_t *conn,
                                  xmpp_stanza_t *stanza,
                                  void *userdata)
{
    const char *name;

    UNUSED(userdata);

    xmpp_timed_handler_delete(conn, _handle_missing_handshake);

    name = xmpp_stanza_get_name(stanza);
    if (strcmp(name, "handshake") != 0) {
        char *msg;
        size_t msg_size;
        xmpp_stanza_to_text(stanza, &msg, &msg_size);
        if (msg) {
            xmpp_debug(conn->ctx, "auth", "Handshake failed: %s", msg);
            xmpp_free(conn->ctx, msg);
        }
        xmpp_disconnect(conn);
        return XMPP_EINT;
    } else {
        conn->authenticated = 1;
        conn->conn_handler(conn, XMPP_CONN_CONNECT, 0, NULL, conn->userdata);
    }

    /* We don't need this handler anymore, return 0 so it can be deleted
     * from the list of handlers.
     */
    return 0;
}

int _handle_missing_handshake(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    xmpp_error(conn->ctx, "xmpp", "Server did not reply to handshake request.");
    xmpp_disconnect(conn);
    return 0;
}

void auth_handle_open_raw(xmpp_conn_t *conn)
{
    handler_reset_timed(conn, 0);
    /* user handlers are not called before authentication is completed. */
    conn->authenticated = 1;
    conn->conn_handler(conn, XMPP_CONN_CONNECT, 0, NULL, conn->userdata);
}

void auth_handle_open_stub(xmpp_conn_t *conn)
{
    xmpp_warn(conn->ctx, "auth", "Stub callback is called.");
}
