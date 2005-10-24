/* auth.c
** libstrophe XMPP client library -- auth functions and handlers
**
** Copyright (C) 2005 OGG, LCC. All rights reserved.
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "sasl.h"

#ifdef _WIN32
#define strcasecmp stricmp
#endif

/* FIXME: these should be configurable */
#define FEATURES_TIMEOUT 2000 /* 2 seconds */
#define BIND_TIMEOUT 2000 /* 2 seconds */
#define SESSION_TIMEOUT 2000 /* 2 seconds */
#define LEGACY_TIMEOUT 2000 /* 2 seconds */

static void _auth(xmpp_conn_t * const conn);
static void _handle_open_sasl(xmpp_conn_t * const conn);
static int _handle_missing_legacy(xmpp_conn_t * const conn,
				  void * const userdata);
static int _handle_legacy(xmpp_conn_t * const conn,
			  xmpp_stanza_t * const stanza,
			  void * const userdata);
static int _handle_features_sasl(xmpp_conn_t * const conn,
				 xmpp_stanza_t * const stanza,
				 void * const userdata);
static int _handle_digestmd5_default(xmpp_conn_t * const conn,
			xmpp_stanza_t * const stanza,
			void * const userdata);
static int _handle_digestmd5_challenge(xmpp_conn_t * const conn,
			xmpp_stanza_t * const stanza,
			void * const userdata);
static int _handle_digestmd5_rspauth(xmpp_conn_t * const conn,
			xmpp_stanza_t * const stanza,
			void * const userdata);

static int _handle_missing_features_sasl(xmpp_conn_t * const conn,
					 void * const userdata);
static int _handle_missing_bind(xmpp_conn_t * const conn,
				void * const userdata);
static int _handle_bind(xmpp_conn_t * const conn,
			xmpp_stanza_t * const stanza,
			void * const userdata);
static int _handle_session(xmpp_conn_t * const conn,
			   xmpp_stanza_t * const stanza,
			   void * const userdata);
static int _handle_missing_session(xmpp_conn_t * const conn,
				   void * const userdata);

/* stream:features handlers */

static int _handle_missing_features(xmpp_conn_t * const conn,
				    void * const userdata)
{
    xmpp_debug(conn->ctx, "xmpp", "didn't get stream features");

    /* legacy auth will be attempted */
    _auth(conn);

    return 0;
}

static int _handle_features(xmpp_conn_t * const conn,
			    xmpp_stanza_t * const stanza,
			    void * const userdata)
{
    xmpp_stanza_t *child, *mech;
    char *text;

    /* remove the handler that detects missing stream:features */
    xmpp_timed_handler_delete(conn, _handle_missing_features);

    /* check for TLS */
    child = xmpp_stanza_get_child_by_name(stanza, "starttls");
    if (child && (strcmp(xmpp_stanza_get_ns(child), XMPP_NS_TLS) == 0))
	conn->tls_support = 1;

    /* check for SASL */
    child = xmpp_stanza_get_child_by_name(stanza, "mechanisms");
    if (child && (strcmp(xmpp_stanza_get_ns(child), XMPP_NS_SASL) == 0)) {
	for (mech = xmpp_stanza_get_children(child); mech; 
	     mech = xmpp_stanza_get_next(mech)) {
	    if (strcmp(xmpp_stanza_get_name(mech), "mechanism") == 0) {
		text = xmpp_stanza_get_text(mech);
		if (strcasecmp(text, "PLAIN") == 0)
		    conn->sasl_support |= SASL_MASK_PLAIN;
		else if (strcasecmp(text, "DIGEST-MD5") == 0)
		    conn->sasl_support |= SASL_MASK_DIGESTMD5;

		xmpp_free(conn->ctx, text);
	    }
	}
    }

    /* TODO: Implement TLS */

    _auth(conn);

    return 0;
}

/* returns the correct auth id for a component or a client.
 * returned string must be freed by caller */
static char *_get_authid(xmpp_conn_t * const conn)
{
    char *authid = NULL;

    if (conn->type == XMPP_CLIENT) {
	/* authid is the node portion of jid */
	if (!conn->jid) return NULL;
	authid = xmpp_jid_node(conn->ctx, conn->jid);
    }

    return authid;
}

static int _handle_digestmd5_default(xmpp_conn_t * const conn,
			      xmpp_stanza_t * const stanza,
			      void * const userdata)
{
    char *name;
    int ret = 1;

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp",
	"handle digest-md5 (default) called for %s", name);

    if (strcmp(name, "failure") == 0) {
	/* TODO: handle errors */
	xmpp_debug(conn->ctx, "xmpp", "SASL DIGEST-MD5 auth failed!");
	/* fall back to next auth method */
	_auth(conn);

	/* remove handler */
	ret = 0;
    } else if (strcmp(name, "success") == 0) {
	/* SASL DIGEST-MD5 auth successful, we need to restart the stream */
	xmpp_debug(conn->ctx, "xmpp", "SASL DIGEST-MD5 auth successful");

	/* reset parser */
	parser_prepare_reset(conn, _handle_open_sasl);

	/* send stream tag */
	conn_open_stream(conn);

	/* remove handler */
	ret = 0;
    } else {
	/* got unexpected reply */
	xmpp_error(conn->ctx, "xmpp", "Got unexpected reply to SASL "
		   "DIGEST-MD5 authentication.");
	xmpp_disconnect(conn);

	/* remove handler */
	ret = 0;
    }

    return ret;
}

/* handle the challenge phase of digest auth */
static int _handle_digestmd5_challenge(xmpp_conn_t * const conn,
			      xmpp_stanza_t * const stanza,
			      void * const userdata)
{
    char *text;
    char *response;
    xmpp_stanza_t *auth, *authdata;
    char *name;

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp",\
	"handle digest-md5 (challenge) called for %s", name);

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

	handler_add(conn, _handle_digestmd5_rspauth, 
		    XMPP_NS_SASL, NULL, NULL, NULL);

	xmpp_send(conn, auth);
	xmpp_stanza_release(auth);

    } else {
	return _handle_digestmd5_default(conn, stanza, userdata);
    }

    /* remove ourselves */
    return 0;
}

/* handle the rspauth phase of digest auth */
static int _handle_digestmd5_rspauth(xmpp_conn_t * const conn,
			      xmpp_stanza_t * const stanza,
			      void * const userdata)
{
    xmpp_stanza_t *auth;
    char *name;

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp",
	"handle digest-md5 (rspauth) called for %s", name);


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
	return _handle_digestmd5_default(conn, stanza, userdata);
    }

    return 1;
}

static int _handle_plain(xmpp_conn_t * const conn,
			  xmpp_stanza_t * const stanza,
			  void * const userdata)
{
    char *name;
    int ret = 1;

    name = xmpp_stanza_get_name(stanza);
    xmpp_debug(conn->ctx, "xmpp", "handle plain called for %s", name);

    /* the server should send a <success> or <failure> stanza */
    if (strcmp(name, "failure") == 0) {
	/* TODO: handle errors */

	/* fall back to next auth method */
	_auth(conn);
    } else if (strcmp(name, "success") == 0) {
	/* SASL PLAIN auth successful, we need to restart the stream */
	xmpp_debug(conn->ctx, "xmpp", "SASL PLAIN auth successful");

	/* reset parser */
	parser_prepare_reset(conn, _handle_open_sasl);

	/* remove this handler */
	ret = 0;

	/* send stream tag */
	conn_open_stream(conn);
    } else {
	/* got unexpected reply */
	xmpp_error(conn->ctx, "xmpp", "Got unexpected reply to SASL PLAIN "\
		   "authentication.");
	xmpp_disconnect(conn);
	ret = 0;
    }

    return ret;
}

static xmpp_stanza_t *_make_sasl_auth(xmpp_conn_t * const conn,
				 const char * const mechanism)
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
 * method fails */
static void _auth(xmpp_conn_t * const conn)
{
    xmpp_stanza_t *auth, *authdata, *query, *child, *iq;
    char *str, *authid;

    if (conn->sasl_support & SASL_MASK_DIGESTMD5) {
	auth = _make_sasl_auth(conn, "DIGEST-MD5");
	if (!auth) {
	    disconnect_mem_error(conn);
	    return;

	}

	handler_add(conn, _handle_digestmd5_challenge, 
		    XMPP_NS_SASL, NULL, NULL, NULL);

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

	xmpp_stanza_add_child(auth, authdata);
	xmpp_stanza_release(authdata);

	handler_add(conn, _handle_plain,
		    XMPP_NS_SASL, NULL, NULL, NULL);

	xmpp_send(conn, auth);
	xmpp_stanza_release(auth);

	/* SASL PLAIN was tried */
	conn->sasl_support &= ~SASL_MASK_PLAIN;
    } else if (conn->type == XMPP_CLIENT) {
	/* legacy client authentication */
	
	iq = xmpp_stanza_new(conn->ctx);
	if (!iq) {
	    disconnect_mem_error(conn);
	    return;
	}
	xmpp_stanza_set_name(iq, "iq");
	xmpp_stanza_set_type(iq, "set");
	xmpp_stanza_set_id(iq, "_xmpp_auth1");

	query = xmpp_stanza_new(conn->ctx);
	if (!query) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	xmpp_stanza_set_name(query, "query");
	xmpp_stanza_set_ns(query, XMPP_NS_AUTH);
	xmpp_stanza_add_child(iq, query);
	xmpp_stanza_release(query);

	child = xmpp_stanza_new(conn->ctx);
	if (!child) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	xmpp_stanza_set_name(child, "username");
	xmpp_stanza_add_child(query, child);
	xmpp_stanza_release(child);

	authdata = xmpp_stanza_new(conn->ctx);
	if (!authdata) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	str = xmpp_jid_node(conn->ctx, conn->jid);
	xmpp_stanza_set_text(authdata, str);
	xmpp_free(conn->ctx, str);
	xmpp_stanza_add_child(child, authdata);
	xmpp_stanza_release(authdata);

	child = xmpp_stanza_new(conn->ctx);
	if (!child) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	xmpp_stanza_set_name(child, "password");
	xmpp_stanza_add_child(query, child);
	xmpp_stanza_release(child);

	authdata = xmpp_stanza_new(conn->ctx);
	if (!authdata) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	xmpp_stanza_set_text(authdata, conn->pass);
	xmpp_stanza_add_child(child, authdata);
	xmpp_stanza_release(authdata);

	child = xmpp_stanza_new(conn->ctx);
	if (!child) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	xmpp_stanza_set_name(child, "resource");
	xmpp_stanza_add_child(query, child);
	xmpp_stanza_release(child);

	authdata = xmpp_stanza_new(conn->ctx);
	if (!authdata) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return;
	}
	str = xmpp_jid_resource(conn->ctx, conn->jid);
	if (str) {
	    xmpp_stanza_set_text(authdata, str);
	    xmpp_free(conn->ctx, str);
	} else {
	    xmpp_stanza_release(authdata);
	    xmpp_stanza_release(iq);
	    xmpp_error(conn->ctx, "auth", 
		       "Cannot authenticate without resource");
	    xmpp_disconnect(conn);
	    return;
	}
	xmpp_stanza_add_child(child, authdata);
	xmpp_stanza_release(authdata);

	handler_add_id(conn, _handle_legacy, "_xmpp_auth1", NULL);
	handler_add_timed(conn, _handle_missing_legacy, 
			  LEGACY_TIMEOUT, NULL);

	xmpp_send(conn, iq);
	xmpp_stanza_release(iq);
    }
}


/* this is called on initial stream open */
void auth_handle_open(xmpp_conn_t * const conn)
{
    /* reset all timed handlers */
    handler_reset_timed(conn, 0);

    /* setup handlers for incoming <stream:features> */
    handler_add(conn, _handle_features,
		NULL, "stream:features", NULL, NULL);
    handler_add_timed(conn, _handle_missing_features,
		      FEATURES_TIMEOUT, NULL);
}

/* called when stream:stream tag received after SASL auth */
static void _handle_open_sasl(xmpp_conn_t * const conn)
{
    xmpp_debug(conn->ctx, "xmpp", "Reopened stream successfully.");

    /* setup stream:features handlers */
    handler_add(conn, _handle_features_sasl,
		NULL, "stream:features", NULL, NULL);
    handler_add_timed(conn, _handle_missing_features_sasl,
		      FEATURES_TIMEOUT, NULL);
}

static int _handle_features_sasl(xmpp_conn_t * const conn,
				 xmpp_stanza_t * const stanza,
				 void * const userdata)
{
    xmpp_stanza_t *bind, *session, *iq, *res, *text;
    char *resource;

    /* remove missing features handler */
    xmpp_timed_handler_delete(conn, _handle_missing_features_sasl);

    /* we are expecting <bind/> and <session/> since this is a
       XMPP style connection */

    bind = xmpp_stanza_get_child_by_name(stanza, "bind");
    if (bind && strcmp(xmpp_stanza_get_ns(bind), XMPP_NS_BIND) == 0) {
	/* resource binding is required */
	conn->bind_required = 1;
    }

    session = xmpp_stanza_get_child_by_name(stanza, "session");
    if (session && strcmp(xmpp_stanza_get_ns(session), XMPP_NS_SESSION) == 0) {
	/* session establishment required */
	conn->session_required = 1;
    }

    /* if bind is required, go ahead and start it */
    if (conn->bind_required) {
	/* bind resource */
	
	/* setup response handlers */
	handler_add_id(conn, _handle_bind, "_xmpp_bind1", NULL);
	handler_add_timed(conn, _handle_missing_bind,
			  BIND_TIMEOUT, NULL);

	/* send bind request */
	iq = xmpp_stanza_new(conn->ctx);
	if (!iq) {
	    disconnect_mem_error(conn);
	    return 0;
	}

	xmpp_stanza_set_name(iq, "iq");
	xmpp_stanza_set_type(iq, "set");
	xmpp_stanza_set_id(iq, "_xmpp_bind1");

	bind = xmpp_stanza_copy(bind);
	if (!bind) {
	    xmpp_stanza_release(iq);
	    disconnect_mem_error(conn);
	    return 0;
	}

	/* request a specific resource if we have one */
        resource = xmpp_jid_resource(conn->ctx, conn->jid);
	if ((resource != NULL) && (strlen(resource) == 0)) {
	    /* j2 doesn't handle an empty resource */
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
	    xmpp_stanza_add_child(bind, res);
	    xmpp_free(conn->ctx, resource);
	}

	xmpp_stanza_add_child(iq, bind);
	xmpp_stanza_release(bind);

	/* send bind request */
	xmpp_send(conn, iq);
	xmpp_stanza_release(iq);
    } else {
	/* can't bind, disconnect */
	xmpp_error(conn->ctx, "xmpp", "Stream features does not allow "\
		   "resource bind.");
	xmpp_disconnect(conn);
    }

    return 0;
}

static int _handle_missing_features_sasl(xmpp_conn_t * const conn,
					 void * const userdata)
{
    xmpp_error(conn->ctx, "xmpp", "Did not receive stream features "\
	       "after SASL authentication.");
    xmpp_disconnect(conn);
    return 0;
}
					  
static int _handle_bind(xmpp_conn_t * const conn,
			xmpp_stanza_t * const stanza,
			void * const userdata)
{
    char *type;
    xmpp_stanza_t *iq, *session;

    /* delete missing bind handler */
    xmpp_timed_handler_delete(conn, _handle_missing_bind);

    /* server has replied to bind request */
    type = xmpp_stanza_get_type(stanza);
    if (type && strcmp(type, "error") == 0) {
	xmpp_error(conn->ctx, "xmpp", "Binding failed.");
	xmpp_disconnect(conn);
    } else if (type && strcmp(type, "result") == 0) {
	/* TODO: extract resource if present */
	xmpp_debug(conn->ctx, "xmpp", "Bind successful.");

	/* establish a session if required */
	if (conn->session_required) {
	    /* setup response handlers */
	    handler_add_id(conn, _handle_session, "_xmpp_session1", NULL);
	    handler_add_timed(conn, _handle_missing_session, 
			      SESSION_TIMEOUT, NULL);

	    /* send session request */
	    iq = xmpp_stanza_new(conn->ctx);
	    if (!iq) {
		disconnect_mem_error(conn);
		return 0;
	    }

	    xmpp_stanza_set_name(iq, "iq");
	    xmpp_stanza_set_type(iq, "set");
	    xmpp_stanza_set_id(iq, "_xmpp_session1");

	    session = xmpp_stanza_new(conn->ctx);
	    if (!session) {
		xmpp_stanza_release(iq);
		disconnect_mem_error(conn);
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

static int _handle_missing_bind(xmpp_conn_t * const conn,
				void * const userdata)
{
    xmpp_error(conn->ctx, "xmpp", "Server did not reply to bind request.");
    xmpp_disconnect(conn);
    return 0;
}

static int _handle_session(xmpp_conn_t * const conn,
			   xmpp_stanza_t * const stanza,
			   void * const userdata)
{
    char *type;

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

static int _handle_missing_session(xmpp_conn_t * const conn,
				   void * const userdata)
{
    xmpp_error(conn->ctx, "xmpp", "Server did not reply to session request.");
    xmpp_disconnect(conn);
    return 0;
}

static int _handle_legacy(xmpp_conn_t * const conn,
			  xmpp_stanza_t * const stanza,
			  void * const userdata)
{
    char *type, *name;

    /* delete missing handler */
    xmpp_timed_handler_delete(conn, _handle_missing_legacy);

    /* server responded to legacy auth request */
    type = xmpp_stanza_get_type(stanza);
    name = xmpp_stanza_get_name(stanza);
    if (!type || strcmp(name, "iq") != 0) {
	xmpp_error(conn->ctx, "xmpp", "Server sent us an unexpected response "\
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
	xmpp_error(conn->ctx, "xmpp", "Server sent us a legacy authentication "\
		   "response with a bad type.");
	xmpp_disconnect(conn);
    }

    return 0;
}

static int _handle_missing_legacy(xmpp_conn_t * const conn,
				  void * const userdata)
{
    xmpp_error(conn->ctx, "xmpp", "Server did not reply to legacy "\
	       "authentication request.");
    xmpp_disconnect(conn);
    return 0;
}
