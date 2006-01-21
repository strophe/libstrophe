/* parser.c
** libstrophe XMPP client library -- xml parser handlers and utility functions
**
** Copyright (C) 2005 OGG, LCC. All rights reserved.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expat.h"

#include "strophe.h"
#include "common.h"

static void _log_open_tag(xmpp_conn_t * const conn,
			  const XML_Char **attr)
{
    char buf[4096];
    size_t len, pos;
    int i;

    pos = 0;
    len = xmpp_snprintf(buf, 4096, "<stream:stream");
    if (len < 0) return;

    pos += len;

    for (i = 0; attr[i]; i += 2) {
	len = xmpp_snprintf(&buf[pos], 4096 - pos, " %s=\"%s\"", 
			    attr[i], attr[i+1]);
	if (len < 0) return;

	pos += len;
    }

    len = xmpp_snprintf(&buf[pos], 4096 - pos, ">");
    if (len < 0) return;

    xmpp_debug(conn->ctx, "xmpp", "RECV: %s", buf);
}

void parser_handle_start(void *userdata,
			 const XML_Char *name,
			 const XML_Char **attr)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    xmpp_stanza_t *child;

    if (conn->depth == 0) {
	/* we're expecting a stream:stream tag. */
	if (strcmp(name, "stream:stream") != 0) {
	    xmpp_error(conn->ctx, "xmpp",
		       "Server did not open valid stream.");
	    conn_disconnect(conn);
	} else {
	    _log_open_tag(conn, attr);

	    if (conn->stream_id) xmpp_free(conn->ctx, conn->stream_id);
	    conn->stream_id = xmpp_strdup(conn->ctx, "foo");
	    if (!conn->stream_id) {
		xmpp_error(conn->ctx, "xmpp",
			   "Memory allocation failure.");
		conn_disconnect(conn);
	    }

	    /* call stream open handler */
	    conn->open_handler(conn);
	}
    } else {
	/* build stanzas at depth 1 */
	if (!conn->stanza && conn->depth != 1) {
	    /* something terrible happened */
	    /* FIXME: shutdown disconnect */
	    xmpp_debug(conn->ctx, "xmpp", "oops, where did our stanza go?");
	} else if (!conn->stanza) {
	    /* starting a new toplevel stanza */
	    conn->stanza = xmpp_stanza_new(conn->ctx);
	    if (!conn->stanza) {
		/* FIXME: can't allocate, disconnect */
	    }
	    xmpp_stanza_set_name(conn->stanza, name);
	    xmpp_stanza_set_attributes(conn->stanza, attr);
	} else {
	    /* starting a child of conn->stanza */
	    child = xmpp_stanza_new(conn->ctx);
	    if (!child) {
		/* FIXME: can't allocate, disconnect */
	    }
	    xmpp_stanza_set_name(child, name);
	    xmpp_stanza_set_attributes(child, attr);

	    /* add child to parent */
	    xmpp_stanza_add_child(conn->stanza, child);
	    
	    /* the child is owned by the toplevel stanza now */
	    xmpp_stanza_release(child);

	    /* make child the current stanza */
	    conn->stanza = child;
	}
    }

    conn->depth++;
}

void parser_handle_end(void *userdata, const XML_Char *name)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    char *buf;
    size_t len;
    xmpp_stanza_t *stanza;

    conn->depth--;

    if (conn->depth == 0) {
	/* got a closing stream tag */
	xmpp_debug(conn->ctx, "xmpp", "RECV: </stream:stream>");
	conn_disconnect_clean(conn);
    } else {
	if (conn->stanza->parent) {
	    /* we're finishing a child stanza, so set current to the parent */
	    conn->stanza = conn->stanza->parent;
	} else {
	    /* we're finishing a toplevel stanza, so fire off handler */
	    if (xmpp_stanza_to_text(conn->stanza, &buf, &len) == 0) {
		xmpp_debug(conn->ctx, "xmpp", "RECV: %s", buf);
		xmpp_free(conn->ctx, buf);
	    }

	    stanza = xmpp_stanza_clone(conn->stanza);
	    xmpp_stanza_release(conn->stanza);
	    conn->stanza = NULL;

	    /* fire handlers */
	    handler_fire_stanza(conn, stanza);

	    xmpp_stanza_release(stanza);
	}
    }
}

void parser_handle_character(void *userdata, const XML_Char *s, int len)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    xmpp_stanza_t *stanza;

    if (conn->depth < 2) return;

    /* create and populate stanza */
    stanza = xmpp_stanza_new(conn->ctx);
    if (!stanza) {
	/* FIXME: allocation error, disconnect */
	return;
    }
    xmpp_stanza_set_text_with_size(stanza, s, len);

    xmpp_stanza_add_child(conn->stanza, stanza);
    xmpp_stanza_release(stanza);
}

/* prepares a parser reset.  this is called from handlers.  we can't
 * reset the parser immediately as it is not reentrant. */
void parser_prepare_reset(xmpp_conn_t * const conn, 
			  xmpp_open_handler handler)
{
    conn->reset_parser = 1;
    conn->open_handler = handler;
}

/* shuts down and restarts XML parser.  true on success */
int parser_reset(xmpp_conn_t * const conn)
{
    conn->reset_parser = 0;

    if (conn->parser)
	XML_ParserFree(conn->parser);

    if (conn->stanza) 
	xmpp_stanza_release(conn->stanza);

    conn->parser = XML_ParserCreate(NULL);
    if (!conn->parser) return 0;

    conn->depth = 0;
    conn->stanza = NULL;
    XML_SetUserData(conn->parser, conn);
    XML_SetElementHandler(conn->parser, parser_handle_start, 
			  parser_handle_end);
    XML_SetCharacterDataHandler(conn->parser, parser_handle_character);

    return 1;
}

