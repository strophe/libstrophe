/* parser.c
** strophe XMPP client library -- xml parser handlers and utility functions
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  XML parser handlers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <strophe.h>
#include "common.h"
#include "parser.h"

struct _parser_t {
    xmpp_ctx_t *ctx;
    xmlParserCtxtPtr xmlctx;
    xmlSAXHandler handlers;
    parser_start_callback startcb;
    parser_end_callback endcb;
    parser_stanza_callback stanzacb;
    void *userdata;
    int depth;
    xmpp_stanza_t *stanza;
};

static void _set_attributes(xmpp_stanza_t *stanza, int nattrs,
                            const xmlChar **attrs)
{
    int i, len;
    char *value;

    if (!attrs) return;

    /* SAX2 uses array of localname/prefix/uri/value_begin/value_end */
    for (i = 0; i < nattrs*5; i += 5) {
        len = attrs[i+4] - attrs[i+3];
        value = xmpp_alloc(stanza->ctx, len + 1);
	if (value) {
	    memcpy(value, attrs[i+3], len);
	    value[len] = '\0';
	    xmpp_stanza_set_attribute(stanza, (const char *)attrs[i], value);
	    xmpp_free(stanza->ctx, value);
	}
    }
}

/* SAX2 gives us the attrs in an incredibly inconvenient array,
 * convert it to what the start callback is expecting */
static char **_convert_attrs(parser_t *parser, int nattrs,
                             const xmlChar **attrs)
{
    int c, i, o, len;
    char *value;
    char **ret;

    if (!attrs) return NULL;

    ret = xmpp_alloc(parser->ctx, (nattrs+1)*2*sizeof(char*));
    if (!ret) return NULL;
    memset(ret, 0, (nattrs+1)*2*sizeof(char*));

    for (c = 0; c < nattrs; c++) {
        i = c * 5;
        o = c * 2;

        len = attrs[i+4] - attrs[i+3];
        value = xmpp_alloc(parser->ctx, len + 1);
        if (value) {
            memcpy(value, attrs[i+3], len);
            value[len] = '\0';
            ret[o] = xmpp_strdup(parser->ctx, (char*)attrs[i]);
            ret[o+1] = value;
        }
    }

    return ret;
}

static void _free_cbattrs(parser_t *parser, char **attrs)
{
    int i;

    if (!attrs)
        return;

    for (i = 0; attrs[i]; i += 2) {
        if (attrs[i]) xmpp_free(parser->ctx, attrs[i]);
        if (attrs[i+1]) xmpp_free(parser->ctx, attrs[i+1]);
    }

    xmpp_free(parser->ctx, attrs);
}

static void _start_element(void *userdata, 
                           const xmlChar *name, const xmlChar *prefix,
                           const xmlChar *uri, int nnamespaces,
                           const xmlChar **namespaces, int nattrs,
                           int ndefaulted, const xmlChar **attrs)
{
    parser_t *parser = (parser_t *)userdata;
    xmpp_stanza_t *child;
    char **cbattrs;

    if (parser->depth == 0) {
        /* notify the owner */
        if (parser->startcb)
            cbattrs = _convert_attrs(parser, nattrs, attrs);
            parser->startcb((char *)name, cbattrs, 
                            parser->userdata);
            _free_cbattrs(parser, cbattrs);
    } else {
	/* build stanzas at depth 1 */
	if (!parser->stanza && parser->depth != 1) {
	    /* something terrible happened */
	    /* FIXME: we should probably trigger a disconnect */
	    xmpp_error(parser->ctx, "parser", "oops, where did our stanza go?");
	} else if (!parser->stanza) {
	    /* starting a new toplevel stanza */
	    parser->stanza = xmpp_stanza_new(parser->ctx);
	    if (!parser->stanza) {
		/* FIXME: can't allocate, disconnect */
	    }
	    xmpp_stanza_set_name(parser->stanza, (char *)name);
	    _set_attributes(parser->stanza, nattrs, attrs);
	    if (uri)
		xmpp_stanza_set_ns(parser->stanza, (char *)uri);
	} else {
	    /* starting a child of conn->stanza */
	    child = xmpp_stanza_new(parser->ctx);
	    if (!child) {
		/* FIXME: can't allocate, disconnect */
	    }
	    xmpp_stanza_set_name(child, (char *)name);
	    _set_attributes(child, nattrs, attrs);
	    if (uri)
		xmpp_stanza_set_ns(child, (char *)uri);

	    /* add child to parent */
	    xmpp_stanza_add_child(parser->stanza, child);
	    
	    /* the child is owned by the toplevel stanza now */
	    xmpp_stanza_release(child);

	    /* make child the current stanza */
	    parser->stanza = child;
	}
    }

    parser->depth++;
}

static void _end_element(void *userdata, const xmlChar *name,
                         const xmlChar *prefix, const xmlChar *uri)
{
    parser_t *parser = (parser_t *)userdata;

    parser->depth--;

    if (parser->depth == 0) {
        /* notify owner */
        if (parser->endcb)
            parser->endcb((char *)name, parser->userdata);
    } else {
	if (parser->stanza->parent) {
	    /* we're finishing a child stanza, so set current to the parent */
	    parser->stanza = parser->stanza->parent;
	} else {
            if (parser->stanzacb)
                parser->stanzacb(parser->stanza,
                                 parser->userdata);
            xmpp_stanza_release(parser->stanza);
            parser->stanza = NULL;
	}
    }
}

static void _characters(void *userdata, const xmlChar *chr, int len)
{
    parser_t *parser = (parser_t *)userdata;
    xmpp_stanza_t *stanza;

    /* skip unimportant whitespace, etc */
    if (parser->depth < 2) return;

    /* create and populate stanza */
    stanza = xmpp_stanza_new(parser->ctx);
    if (!stanza) {
	/* FIXME: allocation error, disconnect */
	return;
    }
    xmpp_stanza_set_text_with_size(stanza, (char *)chr, len);

    xmpp_stanza_add_child(parser->stanza, stanza);
    xmpp_stanza_release(stanza);
}

/* create a new parser */
parser_t *parser_new(xmpp_ctx_t *ctx,
                     parser_start_callback startcb,
                     parser_end_callback endcb,
                     parser_stanza_callback stanzacb,
                     void *userdata)
{
    parser_t *parser;

    parser = xmpp_alloc(ctx, sizeof(parser_t));
    if (parser != NULL) {
        parser->ctx = ctx;
        parser->xmlctx = NULL;
        memset(&parser->handlers, 0, sizeof(xmlSAXHandler));
        parser->handlers.initialized = XML_SAX2_MAGIC;
        parser->handlers.startElementNs = _start_element;
        parser->handlers.endElementNs = _end_element;
        parser->handlers.characters = _characters;
        parser->startcb = startcb;
        parser->endcb = endcb;
        parser->stanzacb = stanzacb;
        parser->userdata = userdata;
        parser->depth = 0;
        parser->stanza = NULL;

        parser_reset(parser);
    }

    return parser;
}

char* parser_attr_name(xmpp_ctx_t *ctx, char *nsname)
{
    return xmpp_strdup(ctx, nsname);
}

/* free a parser */
void parser_free(parser_t *parser)
{
    if (parser->xmlctx)
        xmlFreeParserCtxt(parser->xmlctx);
    xmpp_free(parser->ctx, parser);
}

/* shuts down and restarts XML parser.  true on success */
int parser_reset(parser_t *parser)
{
    if (parser->xmlctx)
        xmlFreeParserCtxt(parser->xmlctx);

    if (parser->stanza) 
	xmpp_stanza_release(parser->stanza);

    parser->xmlctx = xmlCreatePushParserCtxt(&parser->handlers, 
                                             parser, NULL, 0, NULL);
    if (!parser->xmlctx) return 0;

    parser->depth = 0;
    parser->stanza = NULL;

    return 1;
}

/* feed a chunk of data to the parser */
int parser_feed(parser_t *parser, char *chunk, int len)
{
     /* xmlParseChunk API returns 0 on success which is opposite logic to
       the status returned by parser_feed */
    if(!xmlParseChunk(parser->xmlctx, chunk, len, 0)) {
        return 1;
    } else {
        return 0;
    }
}
