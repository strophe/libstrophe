/* handler.c
** strophe XMPP client library -- event handler management
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Event handler management.
 */

/** @defgroup Handlers Stanza and timed event handlers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "ostypes.h"

/* Remove item from the list pointed by head, but don't free it.
 * There can be a situation when user's handler deletes another handler which
 * is the previous in the list. handler_fire_stanza() and handler_fire_timed()
 * must handle this situation correctly. Current function helps to avoid
 * list corruption in described scenario.
 *
 * TODO Convert handler lists to double-linked lists. Current implementation
 * works for O(n).
 */
static void _handler_item_remove(xmpp_handlist_t **head,
                                 xmpp_handlist_t *item)
{
    xmpp_handlist_t *i = *head;

    if (i == item)
        *head = item->next;
    else if (i != NULL) {
        while (i->next != NULL && i->next != item)
            i = i->next;
        if (i->next == item) {
            i->next = item->next;
        }
    }
}

/** Fire off all stanza handlers that match.
 *  This function is called internally by the event loop whenever stanzas
 *  are received from the XMPP server.
 *
 *  @param conn a Strophe connection object
 *  @param stanza a Strophe stanza object
 */
void handler_fire_stanza(xmpp_conn_t * const conn,
                         xmpp_stanza_t * const stanza)
{
    xmpp_handlist_t *item, *next, *head, *head_old;
    const char *id, *ns, *name, *type;
    int ret;

    /* call id handlers */
    id = xmpp_stanza_get_id(stanza);
    if (id) {
        head = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
        /* enable all added handlers */
        for (item = head; item; item = item->next)
            item->enabled = 1;

        item = head;
        while (item) {
            /* don't fire user handlers until authentication succeeds and
               and skip newly added handlers */
            if ((item->user_handler && !conn->authenticated) || !item->enabled) {
                item = item->next;
                continue;
            }

            ret = ((xmpp_handler)(item->handler))(conn, stanza, item->userdata);
            next = item->next;
            if (!ret) {
                /* handler is one-shot, so delete it */
                head_old = head;
                _handler_item_remove(&head, item);
                if (head != head_old) {
                    /* replace old value */
                    hash_add(conn->id_handlers, id, head);
                }
                xmpp_free(conn->ctx, item->id);
                xmpp_free(conn->ctx, item);
            }
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

    item = conn->handlers;
    while (item) {
        /* don't fire user handlers until authentication succeeds and
           skip newly added handlers */
        if ((item->user_handler && !conn->authenticated) || !item->enabled) {
            item = item->next;
            continue;
        }

        next = item->next;
        if ((!item->ns || (ns && strcmp(ns, item->ns) == 0) ||
             xmpp_stanza_get_child_by_ns(stanza, item->ns)) &&
            (!item->name || (name && strcmp(name, item->name) == 0)) &&
            (!item->type || (type && strcmp(type, item->type) == 0))) {

            ret = ((xmpp_handler)(item->handler))(conn, stanza, item->userdata);
            /* list may be changed during execution of a handler */
            next = item->next;
            if (!ret) {
                /* handler is one-shot, so delete it */
                _handler_item_remove(&conn->handlers, item);
                if (item->ns) xmpp_free(conn->ctx, item->ns);
                if (item->name) xmpp_free(conn->ctx, item->name);
                if (item->type) xmpp_free(conn->ctx, item->type);
                xmpp_free(conn->ctx, item);
            }
        }
        item = next;
    }
}

/** Fire off all timed handlers that are ready.
 *  This function is called internally by the event loop.
 *
 *  @param ctx a Strophe context object
 *
 *  @return the time in milliseconds until the next handler will be ready
 */
uint64_t handler_fire_timed(xmpp_ctx_t * const ctx)
{
    xmpp_connlist_t *connitem;
    xmpp_handlist_t *item, *next;
    xmpp_conn_t *conn;
    uint64_t elapsed, min;
    uint64_t timestamp;
    int ret;

    min = (uint64_t)(-1);

    connitem = ctx->connlist;
    while (connitem) {
        conn = connitem->conn;
        if (conn->state != XMPP_STATE_CONNECTED) {
            connitem = connitem->next;
            continue;
        }

        /* enable all handlers that were added */
        for (item = conn->timed_handlers; item; item = item->next)
            item->enabled = 1;

        item = conn->timed_handlers;
        while (item) {
            /* don't fire user handlers until authentication succeeds and
               skip newly added handlers */
            if ((item->user_handler && !conn->authenticated) || !item->enabled) {
                item = item->next;
                continue;
            }

            next = item->next;
            timestamp = time_stamp();
            elapsed = time_elapsed(item->last_stamp, timestamp);
            if (elapsed >= item->period) {
                /* fire! */
                item->last_stamp = timestamp;
                ret = ((xmpp_timed_handler)item->handler)(conn, item->userdata);
                /* list may be changed during execution of a handler */
                next = item->next;
                if (!ret) {
                    /* delete handler if it returned false */
                    _handler_item_remove(&conn->timed_handlers, item);
                    xmpp_free(conn->ctx, item);
                }
            } else if (min > (item->period - elapsed))
                min = item->period - elapsed;

            item = next;
        }

        connitem = connitem->next;
    }

    return min;
}

/** Reset all timed handlers.
 *  This function is called internally when a connection is successful.
 *
 *  @param conn a Strophe connection object
 *  @param user_only whether to reset all handlers or only user ones
 */
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
        if (item->handler == handler && item->userdata == userdata) {
            xmpp_warn(conn->ctx, "xmpp", "Timed handler already exists.");
            break;
        }
    }
    if (item) return;

    /* build new item */
    item = xmpp_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item) return;

    item->user_handler = user_handler;
    item->handler = handler;
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

/** Delete a timed handler.
 *
 *  @param conn a Strophe connection object
 *  @param handler function pointer to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_timed_handler_delete(xmpp_conn_t * const conn,
                               xmpp_timed_handler handler)
{
    xmpp_handlist_t *item, *prev;

    if (!conn->timed_handlers) return;

    prev = NULL;
    item = conn->timed_handlers;
    while (item) {
        if (item->handler == handler) {
            if (prev)
                prev->next = item->next;
            else
                conn->timed_handlers = item->next;

            xmpp_free(conn->ctx, item);
            item = prev ? prev->next : conn->timed_handlers;
        } else {
            prev = item;
            item = item->next;
        }
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
        if (item->handler == handler && item->userdata == userdata) {
            xmpp_warn(conn->ctx, "xmpp", "Id handler already exists.");
            break;
        }
        item = item->next;
    }
    if (item) return;

    /* build new item */
    item = xmpp_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item) return;

    item->user_handler = user_handler;
    item->handler = handler;
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

/** Delete an id based stanza handler.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *  @param id a string containing the id the handler is for
 *
 *  @ingroup Handlers
 */
void xmpp_id_handler_delete(xmpp_conn_t * const conn,
                            xmpp_handler handler,
                            const char * const id)
{
    xmpp_handlist_t *item, *prev, *next;

    prev = NULL;
    item = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
    if (!item) return;

    while (item) {
        next = item->next;

        if (item->handler == handler) {
            if (prev)
                prev->next = next;
            else {
                hash_drop(conn->id_handlers, id);
                hash_add(conn->id_handlers, id, next);
            }

            xmpp_free(conn->ctx, item->id);
            xmpp_free(conn->ctx, item);
            item = next;
        } else {
            prev = item;
            item = next;
        }
    }
}

/* add a stanza handler */
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
        /* same handler function can process different stanzas and
           distinguish them according to userdata. */
        if (item->handler == handler && item->userdata == userdata) {
            xmpp_warn(conn->ctx, "xmpp", "Stanza handler already exists.");
            break;
        }
    }
    if (item) return;

    /* build new item */
    item = (xmpp_handlist_t *)xmpp_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item) return;

    item->user_handler = user_handler;
    item->handler = handler;
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

/** Delete a stanza handler.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *
 *  @ingroup Handlers
 */
void xmpp_handler_delete(xmpp_conn_t * const conn,
                         xmpp_handler handler)
{
    xmpp_handlist_t *prev, *item;

    if (!conn->handlers) return;

    prev = NULL;
    item = conn->handlers;
    while (item) {
        if (item->handler == handler) {
            if (prev)
                prev->next = item->next;
            else
                conn->handlers = item->next;

            if (item->ns) xmpp_free(conn->ctx, item->ns);
            if (item->name) xmpp_free(conn->ctx, item->name);
            if (item->type) xmpp_free(conn->ctx, item->type);
            xmpp_free(conn->ctx, item);
            item = prev ? prev->next : conn->handlers;
        } else {
            prev = item;
            item = item->next;
        }
    }
}

/** Add a timed handler.
 *  The handler will fire for the first time once the period has elapsed,
 *  and continue firing regularly after that.  Strophe will try its best
 *  to fire handlers as close to the period times as it can, but accuracy
 *  will vary depending on the resolution of the event loop.
 *
 *  If the handler function returns true, it will be kept, and if it
 *  returns false, it will be deleted from the list of handlers.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a timed handler
 *  @param period the time in milliseconds between firings
 *  @param userdata an opaque data pointer that will be passed to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_timed_handler_add(xmpp_conn_t * const conn,
                            xmpp_timed_handler handler,
                            const unsigned long period,
                            void * const userdata)
{
    _timed_handler_add(conn, handler, period, userdata, 1);
}

/** Add a timed system handler.
 *  This function is used to add internal timed handlers and should not be
 *  used outside of the library.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a timed handler
 *  @param period the time in milliseconds between firings
 *  @param userdata an opaque data pointer that will be passed to the handler
 */
void handler_add_timed(xmpp_conn_t * const conn,
                       xmpp_timed_handler handler,
                       const unsigned long period,
                       void * const userdata)
{
    _timed_handler_add(conn, handler, period, userdata, 0);
}

/** Add an id based stanza handler.

 *  This function adds a stanza handler for an &lt;iq/&gt; stanza of
 *  type 'result' or 'error' with a specific id attribute.  This can
 *  be used to handle responses to specific &lt;iq/&gt;s.
 *
 *  If the handler function returns true, it will be kept, and if it
 *  returns false, it will be deleted from the list of handlers.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *  @param id a string with the id
 *  @param userdata an opaque data pointer that will be passed to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_id_handler_add(xmpp_conn_t * const conn,
                         xmpp_handler handler,
                         const char * const id,
                         void * const userdata)
{
    _id_handler_add(conn, handler, id, userdata, 1);
}

/** Add an id based system stanza handler.
 *  This function is used to add internal id based stanza handlers and should
 *  not be used outside of the library.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *  @param id a string with the id
 *  @param userdata an opaque data pointer that will be passed to the handler
 */
void handler_add_id(xmpp_conn_t * const conn,
                    xmpp_handler handler,
                    const char * const id,
                    void * const userdata)
{
    _id_handler_add(conn, handler, id, userdata, 0);
}

/** Add a stanza handler.
 *  This function is used to add a stanza handler to a connection.
 *  The handler will be called when the any of the filters match.  The
 *  name filter matches to the top level stanza name.  The type filter
 *  matches the 'type' attribute of the top level stanza.  The ns
 *  filter matches the namespace ('xmlns' attribute) of either the top
 *  level stanza or any of it's immediate children (this allows you do
 *  handle specific &lt;iq/&gt; stanzas based on the &lt;query/&gt;
 *  child namespace.
 *
 *  If the handler function returns true, it will be kept, and if it
 *  returns false, it will be deleted from the list of handlers.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *  @param ns a string with the namespace to match
 *  @param name a string with the stanza name to match
 *  @param type a string with the 'type' attribute to match
 *  @param userdata an opaque data pointer that will be passed to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_handler_add(xmpp_conn_t * const conn,
                      xmpp_handler handler,
                      const char * const ns,
                      const char * const name,
                      const char * const type,
                      void * const userdata)
{
    _handler_add(conn, handler, ns, name, type, userdata, 1);
}

/** Add a system stanza handler.
 *  This function is used to add internal stanza handlers and should
 *  not be used outside of the library.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *  @param ns a string with the namespace to match
 *  @param name a string with the stanza name to match
 *  @param type a string with the 'type' attribute value to match
 *  @param userdata an opaque data pointer that will be passed to the handler
 */
void handler_add(xmpp_conn_t * const conn,
                 xmpp_handler handler,
                 const char * const ns,
                 const char * const name,
                 const char * const type,
                 void * const userdata)
{
    _handler_add(conn, handler, ns, name, type, userdata, 0);
}

/** Delete all system handlers.
 *  This function is used to reset conn object before re-connecting.
 *
 *  @param conn a Strophe connection object
 */
void handler_system_delete_all(xmpp_conn_t *conn)
{
    xmpp_handlist_t *item, *next, *head, *head_old;
    hash_iterator_t *iter;
    const char *key;
    char *key2 = NULL;

    /* TODO unify all kinds of handlers and avoid copy-paste below */

    item = conn->handlers;
    while (item) {
        if (!item->user_handler) {
            next = item->next;
            _handler_item_remove(&conn->handlers, item);
            if (item->ns) xmpp_free(conn->ctx, item->ns);
            if (item->name) xmpp_free(conn->ctx, item->name);
            if (item->type) xmpp_free(conn->ctx, item->type);
            xmpp_free(conn->ctx, item);
            item = next;
        } else
            item = item->next;
    }

    item = conn->timed_handlers;
    while (item) {
        if (!item->user_handler) {
            next = item->next;
            _handler_item_remove(&conn->timed_handlers, item);
            xmpp_free(conn->ctx, item);
            item = next;
        } else
            item = item->next;
    }

    iter = hash_iter_new(conn->id_handlers);
    key = iter == NULL ? NULL : hash_iter_next(iter);
    while (key != NULL) {
        head = head_old = (xmpp_handlist_t *)hash_get(conn->id_handlers, key);
        item = head;
        while (item) {
            if (!item->user_handler) {
                next = item->next;
                _handler_item_remove(&head, item);
                xmpp_free(conn->ctx, item->id);
                xmpp_free(conn->ctx, item);
                item = next;
            } else
                item = item->next;
        }
        if (head != head_old)
            key2 = xmpp_strdup(conn->ctx, key);
        /* Hash table implementation is not perfect, so we need to find next
           key before dropping current one. Otherwise, we will get access to
           freed memory. */
        key = hash_iter_next(iter);
        if (head != head_old) {
            /* hash_add() replaces value if the key exists */
            if (head != NULL)
                hash_add(conn->id_handlers, key2, head);
            else
                hash_drop(conn->id_handlers, key2);
            xmpp_free(conn->ctx, key2);
        }
    }
    if (iter) hash_iter_release(iter);
}
