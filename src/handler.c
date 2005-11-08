/* handler.c
** libstrophe XMPP client library -- event handler management
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

#ifndef _WIN32
#include <stdint.h>
#else
#include "ostypes.h"
#endif

#include "strophe.h"
#include "common.h"

void handler_fire_stanza(xmpp_conn_t * const conn,
			 xmpp_stanza_t * const stanza)
{
    xmpp_handlist_t *item, *prev;
    char *id, *ns, *name, *type;
    
    /* call id handlers */
    id = xmpp_stanza_get_id(stanza);
    if (id) {
	prev = NULL;
 	item = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
	while (item) {
	    xmpp_handlist_t *next = item->next;

	    if (item->user_handler && !conn->authenticated) {
		item = next;
 		continue;
	    }

	    if (!((xmpp_handler)(item->handler))(conn, stanza, item->userdata)) {
		/* handler is one-shot, so delete it */
		if (prev)
		    prev->next = next;
		else {
		    hash_drop(conn->id_handlers, id);
		    hash_add(conn->id_handlers, id, next);
		}
		xmpp_free(conn->ctx, item);
		item = NULL;
	    }
	    if (item)
		prev = item;
	    item = next;
	}
    }
    
    /* call handlers */
    ns = xmpp_stanza_get_ns(stanza);
    name = xmpp_stanza_get_name(stanza);
    type = xmpp_stanza_get_type(stanza);
    
    /* enable all added handlers */
    for (item = conn->handlers; item; item = item->next)
	item->enabled = 1;

    prev = NULL;
    item = conn->handlers;
    while (item) {
	/* skip newly added handlers */
	if (!item->enabled) {
	    item = item->next;
	    continue;
	}

	/* don't call user handlers until authentication succeeds */
	if (item->user_handler && !conn->authenticated) {
	    item = item->next;
	    continue;
	}

	if ((!item->ns || (ns && strcmp(ns, item->ns) == 0)) &&
	    (!item->name || (name && strcmp(name, item->name) == 0)) &&
	    (!item->type || (type && strcmp(type, item->type) == 0)))
	    if (!((xmpp_handler)(item->handler))(conn, stanza, item->userdata)) {
		/* handler is one-shot, so delete it */
		if (prev)
		    prev->next = item->next;
		else
		    conn->handlers = item->next;
		xmpp_free(conn->ctx, item);
		item = NULL;
	    }
	
	if (item) {
	    prev = item;
	    item = item->next;
	} else if (prev)
	    item = prev->next;
	else
	    item = conn->handlers;
    }
}

/* helper function to fire timed handlers.  returns the 
 * time until the next handler would be fired */
uint64_t handler_fire_timed(xmpp_ctx_t * const ctx)
{
    xmpp_connlist_t *connitem;
    xmpp_handlist_t *handitem, *temp;
    int ret, fired;
    uint64_t elapsed, min;

    min = (uint64_t)(-1);

    connitem = ctx->connlist;
    while (connitem) {
	if (connitem->conn->state != XMPP_STATE_CONNECTED) {
	    connitem = connitem->next;
	    continue;
	}
	
	/* enable all handlers that were added */
	for (handitem = connitem->conn->timed_handlers; handitem;
	     handitem = handitem->next)
	    handitem->enabled = 1;

	handitem = connitem->conn->timed_handlers;
	while (handitem) {
	    /* skip newly added handlers */
	    if (!handitem->enabled) {
		handitem = handitem->next;
		continue;
	    }

	    /* only fire user handlers after authentication */
	    if (handitem->user_handler && !connitem->conn->authenticated) {
		handitem = handitem->next;
		continue;
	    }

	    fired = 0;
	    elapsed = time_elapsed(handitem->last_stamp, time_stamp());
	    if (elapsed >= handitem->period) {
		/* fire! */
		fired = 1;
		handitem->last_stamp = time_stamp();
		ret = ((xmpp_timed_handler)handitem->handler)(connitem->conn, handitem->userdata);
	    } else if (min > (handitem->period - elapsed))
		min = handitem->period - elapsed;
		
	    temp = handitem;
	    handitem = handitem->next;

	    /* delete handler if it returned false */
	    if (fired && !ret)
		xmpp_timed_handler_delete(connitem->conn, temp->handler);
	}

	connitem = connitem->next;
    }

    return min;
}

/* reset timed handlers for a connection.  this is called
 * whenever connection is successful */
void handler_reset_timed(xmpp_conn_t *conn, int user_only)
{
    xmpp_handlist_t *handitem;

    handitem = conn->timed_handlers;
    while (handitem) {
	if ((user_only && handitem->user_handler) || !user_only)
	    handitem->last_stamp = time_stamp();
	
	handitem = handitem->next;
    }
}

static void _timed_handler_add(xmpp_conn_t * const conn,
			       xmpp_timed_handler handler,
			       const unsigned long period,
			       void * const userdata, 
			       const int user_handler)
{
    xmpp_handlist_t *item, *tail;

    /* check if handler is already in the list */
    for (item = conn->timed_handlers; item; item = item->next) {
	if (item->handler == (void *)handler)
	    break;
    }
    if (item) return;

    /* build new item */
    item = xmpp_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item) return;

    item->user_handler = user_handler;
    item->handler = (void *)handler;
    item->userdata = userdata;
    item->enabled = 0;
    item->next = NULL;

    item->period = period;
    item->last_stamp = time_stamp();

    /* append item to list */
    if (!conn->timed_handlers)
	conn->timed_handlers = item;
    else {
	tail = conn->timed_handlers;
	while (tail->next) 
	    tail = tail->next;
	tail->next = item;
    }
}

void xmpp_timed_handler_delete(xmpp_conn_t * const conn,
			       xmpp_timed_handler handler)
{
    xmpp_handlist_t *item, *prev;

    if (!conn->timed_handlers) return;

    prev = NULL;
    item = conn->timed_handlers;
    while (item) {
	if (item->handler == (void *)handler)
	    break;
	prev = item;
	item = item->next;
    }

    if (item) {
	if (prev)
	    prev->next = item->next;
	else
	    conn->timed_handlers = item->next;
	
	xmpp_free(conn->ctx, item);
    }
}

static void _id_handler_add(xmpp_conn_t * const conn,
			 xmpp_handler handler,
			 const char * const id,
			 void * const userdata, int user_handler)
{
    xmpp_handlist_t *item, *tail;

    /* check if handler is already in the list */
    item = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
    while (item) {
	if (item->handler == (void *)handler)
	    break;
	item = item->next;
    }
    if (item) return;

    /* build new item */
    item = xmpp_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item) return;

    item->user_handler = user_handler;
    item->handler = (void *)handler;
    item->userdata = userdata;
    item->enabled = 0;
    item->next = NULL;

    item->id = xmpp_strdup(conn->ctx, id);
    if (!item->id) {
	xmpp_free(conn->ctx, item);
	return;
    }

    /* put on list in hash table */
    tail = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
    if (!tail)
	hash_add(conn->id_handlers, id, item);
    else {
	while (tail->next) 
	    tail = tail->next;
	tail->next = item;
    }
}

void xmpp_id_handler_delete(xmpp_conn_t * const conn,
			    xmpp_handler handler,
			    const char * const id)
{
    xmpp_handlist_t *item, *prev;

    prev = NULL;
    item = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
    if (!item) return;

    while (item) {
	if (item->handler == (void *)handler)
	    break;

	prev = item;
	item = item->next;
    }

    if (item) {
	if (prev)
	    prev->next = item->next;
	else {
	    hash_drop(conn->id_handlers, id);
	    hash_add(conn->id_handlers, id, item->next);
	}
	xmpp_free(conn->ctx, item->id);
	xmpp_free(conn->ctx, item);
    }
}

static void _handler_add(xmpp_conn_t * const conn,
			 xmpp_handler handler,
			 const char * const ns,
			 const char * const name,
			 const char * const type,
			 void * const userdata, int user_handler)
{
    xmpp_handlist_t *item, *tail;

    /* check if handler already in list */
    for (item = conn->handlers; item; item = item->next) {
	if (item->handler == (void *)handler)
	    break;
    }
    if (item) return;

    /* build new item */
    item = (xmpp_handlist_t *)xmpp_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item) return;

    item->user_handler = user_handler;
    item->handler = (void *)handler;
    item->userdata = userdata;
    item->enabled = 0;
    item->next = NULL;
    
    if (ns) {
	item->ns = xmpp_strdup(conn->ctx, ns);
	if (!item->ns) {
	    xmpp_free(conn->ctx, item);
	    return;
	}
    } else
	item->ns = NULL;
    if (name) {
	item->name = xmpp_strdup(conn->ctx, name);
	if (!item->name) {
	    if (item->ns) xmpp_free(conn->ctx, item->ns);
	    xmpp_free(conn->ctx, item);
	    return;
	}
    } else
	item->name = NULL;
    if (type) {
	item->type = xmpp_strdup(conn->ctx, type);
	if (!item->type) {
	    if (item->ns) xmpp_free(conn->ctx, item->ns);
	    if (item->name) xmpp_free(conn->ctx, item->name);
	    xmpp_free(conn->ctx, item);
	}
    } else
	item->type = NULL;

    /* append to list */
    if (!conn->handlers)
	conn->handlers = item;
    else {
	tail = conn->handlers;
	while (tail->next) 
	    tail = tail->next;
	tail->next = item;
    }
}

void xmpp_handler_delete(xmpp_conn_t * const conn,
			 xmpp_handler handler)
{
    xmpp_handlist_t *prev, *item;

    if (!conn->handlers) return;

    prev = NULL;
    item = conn->handlers;
    while (item) {
	if (item->handler == (void *)handler)
	    break;
	
	prev = item;
	item = item->next;
    }

    if (item) {
	if (prev)
	    prev->next = item->next;
	else
	    conn->handlers = item->next;

	if (item->ns) xmpp_free(conn->ctx, item->ns);
	if (item->name) xmpp_free(conn->ctx, item->name);
	if (item->type) xmpp_free(conn->ctx, item->type);
	xmpp_free(conn->ctx, item);
    }
}

void xmpp_timed_handler_add(xmpp_conn_t * const conn,
			    xmpp_timed_handler handler,
			    const unsigned long period,
			    void * const userdata)
{
    _timed_handler_add(conn, handler, period, userdata, 1);
}

void handler_add_timed(xmpp_conn_t * const conn,
		       xmpp_timed_handler handler,
		       const unsigned long period,
		       void * const userdata)
{
    _timed_handler_add(conn, handler, period, userdata, 0);
}

void xmpp_id_handler_add(xmpp_conn_t * const conn,
			 xmpp_handler handler,
			 const char * const id,
			 void * const userdata)
{
    _id_handler_add(conn, handler, id, userdata, 1);
}

void handler_add_id(xmpp_conn_t * const conn,
		    xmpp_handler handler,
		    const char * const id,
		    void * const userdata)
{
    _id_handler_add(conn, handler, id, userdata, 0);
}

void xmpp_handler_add(xmpp_conn_t * const conn,
		      xmpp_handler handler,
		      const char * const ns,
		      const char * const name,
		      const char * const type,
		      void * const userdata)
{
    _handler_add(conn, handler, ns, name, type, userdata, 1);
}

void handler_add(xmpp_conn_t * const conn,
		 xmpp_handler handler,
		 const char * const ns,
		 const char * const name,
		 const char * const type,
		 void * const userdata)
{
    _handler_add(conn, handler, ns, name, type, userdata, 0);
}
