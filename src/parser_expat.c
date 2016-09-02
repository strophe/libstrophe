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

#include <expat.h>

#include <strophe.h>
#include "common.h"
#include "parser.h"

/* Use the Unit Separator to delimit namespace and name in our XML*/
#define NAMESPACE_SEP ('\x1F')

struct _parser_t {
    xmpp_ctx_t *ctx;
    XML_Parser expat;
    parser_start_callback startcb;
    parser_end_callback endcb;
    parser_stanza_callback stanzacb;
    void *userdata;
    int depth;
    xmpp_stanza_t *stanza;
};

/* return allocated string with the name from a delimited
 * namespace/name string */
static char *_xml_name(xmpp_ctx_t *ctx, const char *nsname)
{
    char *result = NULL;
    const char *c;
    size_t len;

    c = strchr(nsname, NAMESPACE_SEP);
    if (c == NULL) return xmpp_strdup(ctx, nsname);

    c++;
    len = strlen(c);
    result = xmpp_alloc(ctx, len + 1);
    if (result != NULL) {
	memcpy(result, c, len);
	result[len] = '\0';
    }

    return result;
}

/* return allocated string with the namespace from a delimited string */
static char *_xml_namespace(xmpp_ctx_t *ctx, const char *nsname)
{
    char *result = NULL;
    const char *c;

    c = strchr(nsname, NAMESPACE_SEP);
    if (c != NULL) {
	result = xmpp_alloc(ctx, (c-nsname) + 1);
	if (result != NULL) {
	    memcpy(result, nsname, (c-nsname));
	    result[c-nsname] = '\0';
	}
    }

    return result;
}

static void _set_attributes(xmpp_stanza_t *stanza, const XML_Char **attrs)
{
    char *attr;
    int i;

    if (!attrs) return;

    for (i = 0; attrs[i]; i += 2) {
        /* namespaced attributes aren't used in xmpp, discard namespace */
        attr = _xml_name(stanza->ctx, attrs[i]);
        xmpp_stanza_set_attribute(stanza, attr, attrs[i+1]);
        xmpp_free(stanza->ctx, attr);
    }
}

static void _start_element(void *userdata,
                           const XML_Char *nsname,
                           const XML_Char **attrs)
{
    parser_t *parser = (parser_t *)userdata;
    xmpp_stanza_t *child;
    char *ns, *name;

    ns = _xml_namespace(parser->ctx, nsname);
    name = _xml_name(parser->ctx, nsname);

    if (parser->depth == 0) {
        /* notify the owner */
        if (parser->startcb)
            parser->startcb((char *)name, (char **)attrs, 
                            parser->userdata);
    } else {
        /* build stanzas at depth 1 */
        if (!parser->stanza && parser->depth != 1) {
            /* something terrible happened */
            /* FIXME: shutdown disconnect */
            xmpp_error(parser->ctx, "parser", "oops, where did our stanza go?");
        } else {
            child = xmpp_stanza_new(parser->ctx);
            if (!child) {
                /* FIXME: can't allocate, disconnect */
            }
            xmpp_stanza_set_name(child, name);
            _set_attributes(child, attrs);
            if (ns)
                xmpp_stanza_set_ns(child, ns);

            if (parser->stanza != NULL) {
                xmpp_stanza_add_child(parser->stanza, child);
                xmpp_stanza_release(child);
            }
            parser->stanza = child;
        }
    }

    if (ns) xmpp_free(parser->ctx, ns);
    if (name) xmpp_free(parser->ctx, name);

    parser->depth++;
}

static void _end_element(void *userdata, const XML_Char *name)
{
    parser_t *parser = (parser_t *)userdata;

    parser->depth--;

    if (parser->depth == 0) {
        /* notify the owner */
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

static void _characters(void *userdata, const XML_Char *s, int len)
{
    parser_t *parser = (parser_t *)userdata;
    xmpp_stanza_t *stanza;

    if (parser->depth < 2) return;

    /* create and populate stanza */
    stanza = xmpp_stanza_new(parser->ctx);
    if (!stanza) {
	/* FIXME: allocation error, disconnect */
	return;
    }
    xmpp_stanza_set_text_with_size(stanza, s, len);

    xmpp_stanza_add_child(parser->stanza, stanza);
    xmpp_stanza_release(stanza);
}

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
        parser->expat = NULL;
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
    return _xml_name(ctx, nsname);
}

/* free a parser */
void parser_free(parser_t *parser)
{
    if (parser->expat)
        XML_ParserFree(parser->expat);

    xmpp_free(parser->ctx, parser);
}

/* shuts down and restarts XML parser.  true on success */
int parser_reset(parser_t *parser)
{
    if (parser->expat)
	XML_ParserFree(parser->expat);

    if (parser->stanza) 
	xmpp_stanza_release(parser->stanza);

    parser->expat = XML_ParserCreateNS(NULL, NAMESPACE_SEP);
    if (!parser->expat) return 0;

    parser->depth = 0;
    parser->stanza = NULL;

    XML_SetUserData(parser->expat, parser);
    XML_SetElementHandler(parser->expat, _start_element, _end_element);
    XML_SetCharacterDataHandler(parser->expat, _characters);

    return 1;
}

int parser_feed(parser_t *parser, char *chunk, int len)
{
    return XML_Parse(parser->expat, chunk, len, 0);
}
