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

typedef int (*xmpp_void_handler)();

/* Remove item from the list pointed by head, but don't free it.
 * There can be a situation when user's handler deletes another handler which
 * is the previous in the list. handler_fire_stanza() and handler_fire_timed()
 * must handle this situation correctly. Current function helps to avoid
 * list corruption in described scenario.
 *
 * TODO Convert handler lists to double-linked lists. Current implementation
 * works for O(n).
 */
static void _handler_item_remove(xmpp_handlist_t **head, xmpp_handlist_t *item)
{
    while (*head) {
        if (*head == item) {
            *head = item->next;
            break;
        }
        head = &(*head)->next;
    }
}

static void _free_handlist_item(xmpp_ctx_t *ctx, xmpp_handlist_t *item)
{
    if (item->u.ns)
        strophe_free(ctx, item->u.ns);
    if (item->u.name)
        strophe_free(ctx, item->u.name);
    if (item->u.type)
        strophe_free(ctx, item->u.type);
    strophe_free(ctx, item);
}

/** Fire off all stanza handlers that match.
 *  This function is called internally by the event loop whenever stanzas
 *  are received from the XMPP server.
 *
 *  @param conn a Strophe connection object
 *  @param stanza a Strophe stanza object
 */
void handler_fire_stanza(xmpp_conn_t *conn, xmpp_stanza_t *stanza)
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
            if ((item->user_handler && !conn->authenticated) ||
                !item->enabled) {
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
                strophe_free(conn->ctx, item->u.id);
                strophe_free(conn->ctx, item);
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
        if ((!item->u.ns || (ns && strcmp(ns, item->u.ns) == 0) ||
             xmpp_stanza_get_child_by_ns(stanza, item->u.ns)) &&
            (!item->u.name || (name && strcmp(name, item->u.name) == 0)) &&
            (!item->u.type || (type && strcmp(type, item->u.type) == 0))) {

            ret = ((xmpp_handler)(item->handler))(conn, stanza, item->userdata);
            /* list may be changed during execution of a handler */
            next = item->next;
            if (!ret) {
                /* handler is one-shot, so delete it */
                _handler_item_remove(&conn->handlers, item);
                _free_handlist_item(conn->ctx, item);
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
uint64_t handler_fire_timed(xmpp_ctx_t *ctx)
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
            if ((item->user_handler && !conn->authenticated) ||
                !item->enabled) {
                item = item->next;
                continue;
            }

            next = item->next;
            timestamp = time_stamp();
            elapsed = time_elapsed(item->u.last_stamp, timestamp);
            if (elapsed >= item->u.period) {
                /* fire! */
                item->u.last_stamp = timestamp;
                ret = ((xmpp_timed_handler)item->handler)(conn, item->userdata);
                /* list may be changed during execution of a handler */
                next = item->next;
                if (!ret) {
                    /* delete handler if it returned false */
                    _handler_item_remove(&conn->timed_handlers, item);
                    strophe_free(ctx, item);
                }
            } else if (min > (item->u.period - elapsed))
                min = item->u.period - elapsed;

            item = next;
        }

        connitem = connitem->next;
    }

    /*
     * Check timed handlers in context. These handlers fire periodically
     * regardless of connections state.
     * TODO Reduce copy-paste.
     */
    item = ctx->timed_handlers;
    while (item) {
        next = item->next;
        timestamp = time_stamp();
        elapsed = time_elapsed(item->u.last_stamp, timestamp);
        if (elapsed >= item->u.period) {
            /* fire! */
            item->u.last_stamp = timestamp;
            ret =
                ((xmpp_global_timed_handler)item->handler)(ctx, item->userdata);
            /* list may be changed during execution of a handler */
            next = item->next;
            if (!ret) {
                /* delete handler if it returned false */
                _handler_item_remove(&ctx->timed_handlers, item);
                strophe_free(ctx, item);
            }
        } else if (min > (item->u.period - elapsed))
            min = item->u.period - elapsed;

        item = next;
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
            handitem->u.last_stamp = time_stamp();

        handitem = handitem->next;
    }
}

static void _timed_handler_add(xmpp_ctx_t *ctx,
                               xmpp_handlist_t **handlers_list,
                               xmpp_void_handler handler,
                               unsigned long period,
                               void *userdata,
                               int user_handler)
{
    xmpp_handlist_t *item;

    /* check if handler is already in the list */
    for (item = *handlers_list; item; item = item->next) {
        if (item->handler == handler && item->userdata == userdata) {
            strophe_warn(ctx, "xmpp", "Timed handler already exists.");
            break;
        }
    }
    if (item)
        return;

    /* build new item */
    item = strophe_alloc(ctx, sizeof(xmpp_handlist_t));
    if (!item)
        return;

    item->user_handler = user_handler;
    item->handler = handler;
    item->userdata = userdata;
    item->enabled = 0;

    item->u.period = period;
    item->u.last_stamp = time_stamp();

    /* append item to list */
    item->next = *handlers_list;
    *handlers_list = item;
}

static void _timed_handler_delete(xmpp_ctx_t *ctx,
                                  xmpp_handlist_t **handlers_list,
                                  xmpp_void_handler handler)
{
    xmpp_handlist_t *item;

    while (*handlers_list) {
        item = *handlers_list;
        if (item->handler == handler) {
            *handlers_list = item->next;
            strophe_free(ctx, item);
        } else {
            handlers_list = &item->next;
        }
    }
}

/** Delete a timed handler.
 *
 *  @param conn a Strophe connection object
 *  @param handler function pointer to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_timed_handler_delete(xmpp_conn_t *conn, xmpp_timed_handler handler)
{
    _timed_handler_delete(conn->ctx, &conn->timed_handlers, handler);
}

static void _id_handler_add(xmpp_conn_t *conn,
                            xmpp_handler handler,
                            const char *id,
                            void *userdata,
                            int user_handler)
{
    xmpp_handlist_t *item, *tail;

    /* check if handler is already in the list */
    item = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
    while (item) {
        if (item->handler == handler && item->userdata == userdata) {
            strophe_warn(conn->ctx, "xmpp", "Id handler already exists.");
            break;
        }
        item = item->next;
    }
    if (item)
        return;

    /* build new item */
    item = strophe_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item)
        return;

    item->user_handler = user_handler;
    item->handler = handler;
    item->userdata = userdata;
    item->enabled = 0;
    item->next = NULL;

    item->u.id = strophe_strdup(conn->ctx, id);
    if (!item->u.id) {
        strophe_free(conn->ctx, item);
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
void xmpp_id_handler_delete(xmpp_conn_t *conn,
                            xmpp_handler handler,
                            const char *id)
{
    xmpp_handlist_t *item, *prev, *next;

    prev = NULL;
    item = (xmpp_handlist_t *)hash_get(conn->id_handlers, id);
    if (!item)
        return;

    while (item) {
        next = item->next;

        if (item->handler == handler) {
            if (prev)
                prev->next = next;
            else {
                hash_drop(conn->id_handlers, id);
                hash_add(conn->id_handlers, id, next);
            }

            strophe_free(conn->ctx, item->u.id);
            strophe_free(conn->ctx, item);
            item = next;
        } else {
            prev = item;
            item = next;
        }
    }
}

static int _dup_string(xmpp_ctx_t *ctx, const char *src, char **dest)
{
    if (src) {
        *dest = strophe_strdup(ctx, src);
        if (!(*dest))
            return 1;
    }
    return 0;
}

/* add a stanza handler */
static void _handler_add(xmpp_conn_t *conn,
                         xmpp_handler handler,
                         const char *ns,
                         const char *name,
                         const char *type,
                         void *userdata,
                         int user_handler)
{
    xmpp_handlist_t *item, *tail;

    /* check if handler already in list */
    for (item = conn->handlers; item; item = item->next) {
        /* same handler function can process different stanzas and
           distinguish them according to userdata. */
        if (item->handler == handler && item->userdata == userdata) {
            strophe_warn(conn->ctx, "xmpp", "Stanza handler already exists.");
            break;
        }
    }
    if (item)
        return;

    /* build new item */
    item = (xmpp_handlist_t *)strophe_alloc(conn->ctx, sizeof(xmpp_handlist_t));
    if (!item)
        return;

    memset(item, 0, sizeof(*item));
    item->user_handler = user_handler;
    item->handler = handler;
    item->userdata = userdata;

    if (_dup_string(conn->ctx, ns, &item->u.ns))
        goto error_out;
    if (_dup_string(conn->ctx, name, &item->u.name))
        goto error_out;
    if (_dup_string(conn->ctx, type, &item->u.type))
        goto error_out;

    /* append to list */
    if (!conn->handlers)
        conn->handlers = item;
    else {
        tail = conn->handlers;
        while (tail->next)
            tail = tail->next;
        tail->next = item;
    }

    return;

error_out:
    _free_handlist_item(conn->ctx, item);
}

/** Delete a stanza handler.
 *
 *  @param conn a Strophe connection object
 *  @param handler a function pointer to a stanza handler
 *
 *  @ingroup Handlers
 */
void xmpp_handler_delete(xmpp_conn_t *conn, xmpp_handler handler)
{
    xmpp_handlist_t *prev, *item;

    if (!conn->handlers)
        return;

    prev = NULL;
    item = conn->handlers;
    while (item) {
        if (item->handler == handler) {
            if (prev)
                prev->next = item->next;
            else
                conn->handlers = item->next;

            _free_handlist_item(conn->ctx, item);
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
void xmpp_timed_handler_add(xmpp_conn_t *conn,
                            xmpp_timed_handler handler,
                            unsigned long period,
                            void *userdata)
{
    _timed_handler_add(conn->ctx, &conn->timed_handlers, handler, period,
                       userdata, 1);
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
void handler_add_timed(xmpp_conn_t *conn,
                       xmpp_timed_handler handler,
                       unsigned long period,
                       void *userdata)
{
    _timed_handler_add(conn->ctx, &conn->timed_handlers, handler, period,
                       userdata, 0);
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
void xmpp_id_handler_add(xmpp_conn_t *conn,
                         xmpp_handler handler,
                         const char *id,
                         void *userdata)
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
void handler_add_id(xmpp_conn_t *conn,
                    xmpp_handler handler,
                    const char *id,
                    void *userdata)
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
void xmpp_handler_add(xmpp_conn_t *conn,
                      xmpp_handler handler,
                      const char *ns,
                      const char *name,
                      const char *type,
                      void *userdata)
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
void handler_add(xmpp_conn_t *conn,
                 xmpp_handler handler,
                 const char *ns,
                 const char *name,
                 const char *type,
                 void *userdata)
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
    const char *key, *key2;

    /* TODO unify all kinds of handlers and avoid copy-paste below */

    item = conn->handlers;
    while (item) {
        if (!item->user_handler) {
            next = item->next;
            _handler_item_remove(&conn->handlers, item);
            _free_handlist_item(conn->ctx, item);
            item = next;
        } else
            item = item->next;
    }

    item = conn->timed_handlers;
    while (item) {
        if (!item->user_handler) {
            next = item->next;
            _handler_item_remove(&conn->timed_handlers, item);
            strophe_free(conn->ctx, item);
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
                strophe_free(conn->ctx, item->u.id);
                strophe_free(conn->ctx, item);
                item = next;
            } else
                item = item->next;
        }
        /* Hash table implementation is not perfect, so we need to find next
           key before dropping current one. Otherwise, we will get access to
           freed memory. */
        key2 = hash_iter_next(iter);
        if (head != head_old) {
            /* hash_add() replaces value if the key exists */
            if (head != NULL)
                hash_add(conn->id_handlers, key, head);
            else
                hash_drop(conn->id_handlers, key);
        }
        key = key2;
    }
    if (iter)
        hash_iter_release(iter);
}

/** Add a global timed handler.
 *  The handler will fire for the first time once the period has elapsed,
 *  and continue firing regularly after that.  Strophe will try its best
 *  to fire handlers as close to the period times as it can, but accuracy
 *  will vary depending on the resolution of the event loop.
 *
 *  The main difference between global and ordinary handlers:
 *  - Ordinary handler is related to a connection, fires only when the
 *    connection is in connected state and is removed once the connection is
 *    destroyed.
 *  - Global handler fires regardless of connections state and is related to
 *    a Strophe context.
 *
 *  The handler is executed in context of the respective event loop.
 *
 *  If the handler function returns true, it will be kept, and if it
 *  returns false, it will be deleted from the list of handlers.
 *
 *  Notice, the same handler pointer may be added multiple times with different
 *  userdata pointers. However, xmpp_global_timed_handler_delete() deletes
 *  all occurrences.
 *
 *  @param ctx a Strophe context object
 *  @param handler a function pointer to a timed handler
 *  @param period the time in milliseconds between firings
 *  @param userdata an opaque data pointer that will be passed to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_global_timed_handler_add(xmpp_ctx_t *ctx,
                                   xmpp_global_timed_handler handler,
                                   unsigned long period,
                                   void *userdata)
{
    _timed_handler_add(ctx, &ctx->timed_handlers, handler, period, userdata, 1);
}

/** Delete a global timed handler.
 *
 *  @param ctx a Strophe context object
 *  @param handler function pointer to the handler
 *
 *  @ingroup Handlers
 */
void xmpp_global_timed_handler_delete(xmpp_ctx_t *ctx,
                                      xmpp_global_timed_handler handler)
{
    _timed_handler_delete(ctx, &ctx->timed_handlers, handler);
}
