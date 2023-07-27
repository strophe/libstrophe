/* stanza.c
** strophe XMPP client library -- XMPP stanza object and utilities
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Stanza creation and manipulation.
 */

/** @defgroup Stanza Stanza creation and manipulation
 */

#include <stdio.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "hash.h"
#include "parser.h"

/** Create a stanza object.
 *  This function allocates and initializes a blank stanza object.
 *  The stanza will have a reference count of one, so the caller does not
 *  need to clone it.
 *
 *  @param ctx a Strophe context object
 *
 *  @return a stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_new(xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *stanza;

    stanza = strophe_alloc(ctx, sizeof(xmpp_stanza_t));
    if (stanza != NULL) {
        stanza->ref = 1;
        stanza->ctx = ctx;
        stanza->type = XMPP_STANZA_UNKNOWN;
        stanza->prev = NULL;
        stanza->next = NULL;
        stanza->children = NULL;
        stanza->parent = NULL;
        stanza->data = NULL;
        stanza->attributes = NULL;
    }

    return stanza;
}

/** Clone a stanza object.
 *  This function increments the reference count of the stanza object.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return the stanza object with it's reference count incremented
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_clone(xmpp_stanza_t *stanza)
{
    stanza->ref++;

    return stanza;
}

/*
 * Copy the attributes of stanza src into stanza dst. Return -1 on error.
 */
static int _stanza_copy_attributes(xmpp_stanza_t *dst, const xmpp_stanza_t *src)
{
    hash_iterator_t *iter;
    const char *key;
    const char *val;
    int rc = XMPP_EOK;

    iter = hash_iter_new(src->attributes);
    if (!iter)
        rc = XMPP_EMEM;

    while (rc == XMPP_EOK && (key = hash_iter_next(iter))) {
        val = hash_get(src->attributes, key);
        if (!val)
            rc = XMPP_EINT;
        if (rc == XMPP_EOK)
            rc = xmpp_stanza_set_attribute(dst, key, val);
    }
    hash_iter_release(iter);

    if (rc != XMPP_EOK && dst->attributes) {
        hash_release(dst->attributes);
        dst->attributes = NULL;
    }
    return rc;
}

/** Copy a stanza and its children.
 *  This function copies a stanza along with all its children and returns
 *  the new stanza and children with a reference count of 1.  The returned
 *  stanza will have no parent and no siblings.  This function is useful
 *  for extracting a child stanza for inclusion in another tree.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_copy(const xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *copy, *child, *copychild, *tail;

    copy = xmpp_stanza_new(stanza->ctx);
    if (!copy)
        goto copy_error;

    copy->type = stanza->type;

    if (stanza->data) {
        copy->data = strophe_strdup(stanza->ctx, stanza->data);
        if (!copy->data)
            goto copy_error;
    }

    if (stanza->attributes) {
        if (_stanza_copy_attributes(copy, stanza) == -1)
            goto copy_error;
    }

    tail = copy->children;
    for (child = stanza->children; child; child = child->next) {
        copychild = xmpp_stanza_copy(child);
        if (!copychild)
            goto copy_error;
        copychild->parent = copy;

        if (tail) {
            copychild->prev = tail;
            tail->next = copychild;
        } else
            copy->children = copychild;
        tail = copychild;
    }

    return copy;

copy_error:
    /* release all the hitherto allocated memory */
    if (copy)
        xmpp_stanza_release(copy);
    return NULL;
}

/** Release a stanza object and all of its children.
 *  This function releases a stanza object and potentially all of its
 *  children, which may cause the object(s) to be freed.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return TRUE if the object was freed and FALSE otherwise
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_release(xmpp_stanza_t *stanza)
{
    int released = 0;
    xmpp_stanza_t *child, *tchild;

    /* release stanza */
    if (stanza->ref > 1)
        stanza->ref--;
    else {
        /* release all children */
        child = stanza->children;
        while (child) {
            tchild = child;
            child = child->next;
            tchild->next = NULL;
            xmpp_stanza_release(tchild);
        }

        if (stanza->attributes)
            hash_release(stanza->attributes);
        if (stanza->data)
            strophe_free(stanza->ctx, stanza->data);
        strophe_free(stanza->ctx, stanza);
        released = 1;
    }

    return released;
}

/** Get the strophe context that the stanza is associated with.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a Strophe context
 *
 *  @ingroup Stanza
 */
xmpp_ctx_t *xmpp_stanza_get_context(const xmpp_stanza_t *stanza)
{
    return stanza->ctx;
}

/** Determine if a stanza is a text node.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return TRUE if the stanza is a text node, FALSE otherwise
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_is_text(xmpp_stanza_t *stanza)
{
    return (stanza && stanza->type == XMPP_STANZA_TEXT);
}

/** Determine if a stanza is a tag node.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return TRUE if the stanza is a tag node, FALSE otherwise
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_is_tag(xmpp_stanza_t *stanza)
{
    return (stanza && stanza->type == XMPP_STANZA_TAG);
}

/* Escape a string with for use in a XML text node or attribute. Assumes that
 * the input string is encoded in UTF-8. On success, returns a pointer to a
 * buffer with the resulting data which must be xmpp_free()'d by the caller.
 * On failure, returns NULL.
 */

static char *_escape_xml(xmpp_ctx_t *ctx, char *text)
{
    size_t len = 0;
    char *src;
    char *dst;
    char *buf;
    for (src = text; *src != '\0'; src++) {
        switch (*src) {
        case '<': /* "&lt;" */
        case '>': /* "&gt;" */
            len += 4;
            break;
        case '&': /* "&amp;" */
            len += 5;
            break;
        case '"':
            len += 6; /*"&quot;" */
            break;
        default:
            len++;
        }
    }
    if ((buf = strophe_alloc(ctx, (len + 1) * sizeof(char))) == NULL)
        return NULL; /* Error */
    dst = buf;
    for (src = text; *src != '\0'; src++) {
        switch (*src) {
        case '<':
            strcpy(dst, "&lt;");
            dst += 4;
            break;
        case '>':
            strcpy(dst, "&gt;");
            dst += 4;
            break;
        case '&':
            strcpy(dst, "&amp;");
            dst += 5;
            break;
        case '"':
            strcpy(dst, "&quot;");
            dst += 6;
            break;
        default:
            *dst = *src;
            dst++;
        }
    }
    *dst = '\0';
    return buf;
}

/* small helper function */
static void _render_update(
    int *written, int length, int lastwrite, size_t *left, char **ptr)
{
    *written += lastwrite;

    if (*written >= length) {
        *left = 0;
        *ptr = NULL;
    } else {
        *left -= lastwrite;
        *ptr = &(*ptr)[lastwrite];
    }
}

/* always returns number of bytes written or that would have been
 * written if the buffer was large enough
 * return values < 0 indicate some error occurred,
 * and return values > buflen indicate buffer was not large enough
 */
static int
_render_stanza_recursive(xmpp_stanza_t *stanza, char *buf, size_t buflen)
{
    char *ptr = buf;
    size_t left = buflen;
    int ret, written;
    xmpp_stanza_t *child;
    hash_iterator_t *iter;
    const char *key;
    char *tmp;

    written = 0;

    if (stanza->type == XMPP_STANZA_UNKNOWN)
        return XMPP_EINVOP;

    if (stanza->type == XMPP_STANZA_TEXT) {
        if (!stanza->data)
            return XMPP_EINVOP;

        tmp = _escape_xml(stanza->ctx, stanza->data);
        if (tmp == NULL)
            return XMPP_EMEM;
        ret = strophe_snprintf(ptr, left, "%s", tmp);
        strophe_free(stanza->ctx, tmp);
        if (ret < 0)
            return XMPP_EMEM;
        _render_update(&written, buflen, ret, &left, &ptr);
    } else { /* stanza->type == XMPP_STANZA_TAG */
        if (!stanza->data)
            return XMPP_EINVOP;

        /* write beginning of tag and attributes */
        ret = strophe_snprintf(ptr, left, "<%s", stanza->data);
        if (ret < 0)
            return XMPP_EMEM;
        _render_update(&written, buflen, ret, &left, &ptr);

        if (stanza->attributes && hash_num_keys(stanza->attributes) > 0) {
            iter = hash_iter_new(stanza->attributes);
            while ((key = hash_iter_next(iter))) {
                if (!strcmp(key, "xmlns")) {
                    /* don't output namespace if parent stanza is the same */
                    if (stanza->parent && stanza->parent->attributes &&
                        hash_get(stanza->parent->attributes, key) &&
                        !strcmp(
                            (char *)hash_get(stanza->attributes, key),
                            (char *)hash_get(stanza->parent->attributes, key)))
                        continue;
                    /* or if this is the stream namespace */
                    if (!stanza->parent &&
                        !strcmp((char *)hash_get(stanza->attributes, key),
                                XMPP_NS_CLIENT))
                        continue;
                }
                tmp = _escape_xml(stanza->ctx,
                                  (char *)hash_get(stanza->attributes, key));
                if (tmp == NULL) {
                    hash_iter_release(iter);
                    return XMPP_EMEM;
                }
                ret = strophe_snprintf(ptr, left, " %s=\"%s\"", key, tmp);
                strophe_free(stanza->ctx, tmp);
                if (ret < 0) {
                    hash_iter_release(iter);
                    return XMPP_EMEM;
                }
                _render_update(&written, buflen, ret, &left, &ptr);
            }
            hash_iter_release(iter);
        }

        if (!stanza->children) {
            /* write end if singleton tag */
            ret = strophe_snprintf(ptr, left, "/>");
            if (ret < 0)
                return XMPP_EMEM;
            _render_update(&written, buflen, ret, &left, &ptr);
        } else {
            /* this stanza has child stanzas */

            /* write end of start tag */
            ret = strophe_snprintf(ptr, left, ">");
            if (ret < 0)
                return XMPP_EMEM;
            _render_update(&written, buflen, ret, &left, &ptr);

            /* iterate and recurse over child stanzas */
            child = stanza->children;
            while (child) {
                ret = _render_stanza_recursive(child, ptr, left);
                if (ret < 0)
                    return ret;

                _render_update(&written, buflen, ret, &left, &ptr);

                child = child->next;
            }

            /* write end tag */
            ret = strophe_snprintf(ptr, left, "</%s>", stanza->data);
            if (ret < 0)
                return XMPP_EMEM;

            _render_update(&written, buflen, ret, &left, &ptr);
        }
    }

    return written;
}

/** Render a stanza object to text.
 *  This function renders a given stanza object, along with its
 *  children, to text.  The text is returned in an allocated,
 *  null-terminated buffer.  It starts by allocating a 1024 byte buffer
 *  and reallocates more memory if that is not large enough.
 *
 *  @param stanza a Strophe stanza object
 *  @param buf a reference to a string pointer
 *  @param buflen a reference to a size_t
 *
 *  @return 0 on success (XMPP_EOK), and a number less than 0 on failure
 *      (XMPP_EMEM, XMPP_EINVOP)
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_to_text(xmpp_stanza_t *stanza, char **buf, size_t *buflen)
{
    char *buffer, *tmp;
    size_t length;
    int ret;

    /* allocate a default sized buffer and attempt to render */
    length = 1024;
    buffer = strophe_alloc(stanza->ctx, length);
    if (!buffer) {
        *buf = NULL;
        *buflen = 0;
        return XMPP_EMEM;
    }

    ret = _render_stanza_recursive(stanza, buffer, length);
    if (ret < 0) {
        strophe_free(stanza->ctx, buffer);
        *buf = NULL;
        *buflen = 0;
        return ret;
    }

    if ((size_t)ret > length - 1) {
        tmp = strophe_realloc(stanza->ctx, buffer, ret + 1);
        if (!tmp) {
            strophe_free(stanza->ctx, buffer);
            *buf = NULL;
            *buflen = 0;
            return XMPP_EMEM;
        }
        length = ret + 1;
        buffer = tmp;

        ret = _render_stanza_recursive(stanza, buffer, length);
        if ((size_t)ret > length - 1) {
            strophe_free(stanza->ctx, buffer);
            *buf = NULL;
            *buflen = 0;
            return XMPP_EMEM;
        }
    }

    buffer[length - 1] = 0;

    *buf = buffer;
    *buflen = ret;

    return XMPP_EOK;
}

/** Set the name of a stanza.
 *
 *  @param stanza a Strophe stanza object
 *  @param name a string with the name of the stanza
 *
 *  @return XMPP_EOK on success, a number less than 0 on failure (XMPP_EMEM,
 *      XMPP_EINVOP)
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_name(xmpp_stanza_t *stanza, const char *name)
{
    if (stanza->type == XMPP_STANZA_TEXT)
        return XMPP_EINVOP;

    if (stanza->data)
        strophe_free(stanza->ctx, stanza->data);

    stanza->type = XMPP_STANZA_TAG;
    stanza->data = strophe_strdup(stanza->ctx, name);

    return stanza->data == NULL ? XMPP_EMEM : XMPP_EOK;
}

/** Get the stanza name.
 *  This function returns a pointer to the stanza name.  If the caller needs
 *  to store this data, it must make a copy.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a string with the stanza name
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_name(xmpp_stanza_t *stanza)
{
    if (stanza->type == XMPP_STANZA_TEXT)
        return NULL;
    return stanza->data;
}

/** Count the attributes in a stanza object.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return the number of attributes for the stanza object
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_get_attribute_count(xmpp_stanza_t *stanza)
{
    if (stanza->attributes == NULL) {
        return 0;
    }

    return hash_num_keys(stanza->attributes);
}

/** Get all attributes for a stanza object.
 *  This function populates the array with attributes from the stanza.  The
 *  attr array will be in the format:  attr[i] = attribute name,
 *  attr[i+1] = attribute value.
 *
 *  @param stanza a Strophe stanza object
 *  @param attr the string array to populate
 *  @param attrlen the size of the array
 *
 *  @return the number of slots used in the array, which will be 2 times the
 *      number of attributes in the stanza
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_get_attributes(xmpp_stanza_t *stanza,
                               const char **attr,
                               int attrlen)
{
    hash_iterator_t *iter;
    const char *key;
    int num = 0;

    if (stanza->attributes == NULL) {
        return 0;
    }

    iter = hash_iter_new(stanza->attributes);
    while ((key = hash_iter_next(iter)) != NULL && attrlen) {
        attr[num++] = key;
        attrlen--;
        if (attrlen == 0) {
            hash_iter_release(iter);
            return num;
        }
        attr[num++] = hash_get(stanza->attributes, key);
        attrlen--;
        if (attrlen == 0) {
            hash_iter_release(iter);
            return num;
        }
    }

    hash_iter_release(iter);
    return num;
}

/** Set an attribute for a stanza object.
 *
 *  @param stanza a Strophe stanza object
 *  @param key a string with the attribute name
 *  @param value a string with the attribute value
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_attribute(xmpp_stanza_t *stanza,
                              const char *key,
                              const char *value)
{
    char *val;
    int rc;

    if (stanza->type != XMPP_STANZA_TAG)
        return XMPP_EINVOP;

    if (!stanza->attributes) {
        stanza->attributes = hash_new(stanza->ctx, 8, strophe_free);
        if (!stanza->attributes)
            return XMPP_EMEM;
    }

    val = strophe_strdup(stanza->ctx, value);
    if (!val) {
        return XMPP_EMEM;
    }

    rc = hash_add(stanza->attributes, key, val);
    if (rc < 0) {
        strophe_free(stanza->ctx, val);
        return XMPP_EMEM;
    }

    return XMPP_EOK;
}

/** Set the stanza namespace.
 *  This is a convenience function equivalent to calling:
 *  xmpp_stanza_set_attribute(stanza, "xmlns", ns);
 *
 *  @param stanza a Strophe stanza object
 *  @param ns a string with the namespace
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_ns(xmpp_stanza_t *stanza, const char *ns)
{
    return xmpp_stanza_set_attribute(stanza, "xmlns", ns);
}

/** Add a child stanza to a stanza object.
 *  If do_clone is TRUE, user keeps reference to the child stanza and must call
 *  xmpp_stanza_release() to release the reference. If do_clone is FALSE, user
 *  transfers ownership and must not neither call xmpp_stanza_release() for
 *  the child stanza nor use it.
 *
 *  @param stanza a Strophe stanza object
 *  @param child the child stanza object
 *  @param do_clone TRUE to increase ref count of child (default for
 *                  xmpp_stanza_add_child())
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_add_child_ex(xmpp_stanza_t *stanza,
                             xmpp_stanza_t *child,
                             int do_clone)
{
    xmpp_stanza_t *s;

    if (do_clone) {
        /* get a reference to the child */
        xmpp_stanza_clone(child);
    }

    child->parent = stanza;

    if (!stanza->children)
        stanza->children = child;
    else {
        s = stanza->children;
        while (s->next)
            s = s->next;
        s->next = child;
        child->prev = s;
    }

    return XMPP_EOK;
}

/** Add a child stanza to a stanza object.
 *  This function clones the child and appends it to the stanza object's
 *  children.
 *
 *  @param stanza a Strophe stanza object
 *  @param child the child stanza object
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_add_child(xmpp_stanza_t *stanza, xmpp_stanza_t *child)
{
    return xmpp_stanza_add_child_ex(stanza, child, 1);
}

/** Set the text data for a text stanza.
 *  This function copies the text given and sets the stanza object's text to
 *  it.  Attempting to use this function on a stanza that has a name will
 *  fail with XMPP_EINVOP.  This function takes the text as a null-terminated
 *  string.
 *
 *  @param stanza a Strophe stanza object
 *  @param text a string with the text
 *
 *  @return XMPP_EOK (0) on success or a number less than zero on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_text(xmpp_stanza_t *stanza, const char *text)
{
    if (stanza->type == XMPP_STANZA_TAG)
        return XMPP_EINVOP;

    stanza->type = XMPP_STANZA_TEXT;

    if (stanza->data)
        strophe_free(stanza->ctx, stanza->data);
    stanza->data = strophe_strdup(stanza->ctx, text);

    return stanza->data == NULL ? XMPP_EMEM : XMPP_EOK;
}

/** Set the text data for a text stanza.
 *  This function copies the text given and sets the stanza object's text to
 *  it.  Attempting to use this function on a stanza that has a name will
 *  fail with XMPP_EINVOP.  This function takes the text as buffer and a length
 *  as opposed to a null-terminated string.
 *
 *  @param stanza a Strophe stanza object
 *  @param text a buffer with the text
 *  @param size the length of the text
 *
 *  @return XMPP_EOK (0) on success and a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_text_with_size(xmpp_stanza_t *stanza,
                                   const char *text,
                                   size_t size)
{
    if (stanza->type == XMPP_STANZA_TAG)
        return XMPP_EINVOP;

    stanza->type = XMPP_STANZA_TEXT;

    if (stanza->data)
        strophe_free(stanza->ctx, stanza->data);
    stanza->data = strophe_alloc(stanza->ctx, size + 1);
    if (!stanza->data)
        return XMPP_EMEM;

    memcpy(stanza->data, text, size);
    stanza->data[size] = 0;

    return XMPP_EOK;
}

/** Get the 'id' attribute of the stanza object.
 *  This is a convenience function equivalent to:
 *  xmpp_stanza_get_attribute(stanza, "id");
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a string with the 'id' attribute value
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_id(xmpp_stanza_t *stanza)
{
    return xmpp_stanza_get_attribute(stanza, "id");
}

/** Get the namespace attribute of the stanza object.
 *  This is a convenience function equivalent to:
 *  xmpp_stanza_get_attribute(stanza, "xmlns");
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a string with the 'xmlns' attribute value
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_ns(xmpp_stanza_t *stanza)
{
    return xmpp_stanza_get_attribute(stanza, "xmlns");
}

/** Get the 'type' attribute of the stanza object.
 *  This is a convenience function equivalent to:
 *  xmpp_stanza_get_attribute(stanza, "type");
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a string with the 'type' attribute value
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_type(xmpp_stanza_t *stanza)
{
    return xmpp_stanza_get_attribute(stanza, "type");
}

/** Get the 'to' attribute of the stanza object.
 *  This is a convenience function equivalent to:
 *  xmpp_stanza_get_attribute(stanza, "to");
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a string with the 'to' attribute value
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_to(xmpp_stanza_t *stanza)
{
    return xmpp_stanza_get_attribute(stanza, "to");
}

/** Get the 'from' attribute of the stanza object.
 *  This is a convenience function equivalent to:
 *  xmpp_stanza_get_attribute(stanza, "from");
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a string with the 'from' attribute value
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_from(xmpp_stanza_t *stanza)
{
    return xmpp_stanza_get_attribute(stanza, "from");
}

/** Get the first child of stanza following a path-like list of names.
 *  This function searches the children and their children that match
 *  the given path.
 *
 *  * "name" - Search 'name'
 *
 *  * "name[@ns='foo']" - Search 'name' which is in the namespace 'foo'
 *
 *  The Syntax to pass namespaces is inspired by the XPATH way of passing
 *  attributes.
 *
 *  The namespace syntax only supports single quotes `'`.
 *
 *  The \ref XMPP_STANZA_NAME_IN_NS macro is provided as a helper for names
 *  in namespaces.
 *
 *  @param stanza a Strophe stanza object
 *  @param ... a var-args list that must be terminated by a NULL entry
 *
 *  @return the matching child stanza object or NULL if no match was found
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_get_child_by_path(xmpp_stanza_t *stanza, ...)
{
    xmpp_stanza_t *child = NULL;
    char *p, *tok, *attr, *saveattr, *ns = NULL;
    const char *xmlns;
    va_list ap;

    va_start(ap, stanza);

    while ((p = va_arg(ap, char *)) != NULL) {
        tok = strophe_strdup(stanza->ctx, p);
        if (!tok) {
            child = NULL;
            break;
        }
        saveattr = ns = NULL;
        attr = strophe_strtok_r(tok, "[", &saveattr);
        if (attr) {
            attr = strophe_strtok_r(NULL, "]", &saveattr);
            if (attr) {
                if (!strncmp(attr, "@ns='", 5)) {
                    ns = attr + 5;
                    strophe_strtok_r(ns, "'", &saveattr);
                }
            }
        }
        if (!child) {
            if (strcmp(xmpp_stanza_get_name(stanza), tok))
                goto error_out;

            if (ns) {
                xmlns = xmpp_stanza_get_ns(stanza);
                if (!xmlns || strcmp(xmlns, ns))
                    goto error_out;
            }
            child = stanza;
        } else {
            if (!ns)
                child = xmpp_stanza_get_child_by_name(child, tok);
            else
                child = xmpp_stanza_get_child_by_name_and_ns(child, tok, ns);
        }
error_out:
        strophe_free(stanza->ctx, tok);
        if (!child)
            break;
    }

    va_end(ap);

    return p == NULL ? child : NULL;
}

/** Get the first child of stanza with name.
 *  This function searches all the immediate children of stanza for a child
 *  stanza that matches the name.  The first matching child is returned.
 *
 *  @param stanza a Strophe stanza object
 *  @param name a string with the name to match
 *
 *  @return the matching child stanza object or NULL if no match was found
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_get_child_by_name(xmpp_stanza_t *stanza,
                                             const char *name)
{
    xmpp_stanza_t *child;

    for (child = stanza->children; child; child = child->next) {
        if (child->type == XMPP_STANZA_TAG &&
            (strcmp(name, xmpp_stanza_get_name(child)) == 0))
            break;
    }

    return child;
}

/** Get the first child of a stanza with a given namespace.
 *  This function searches all the immediate children of a stanza for a child
 *  stanza that matches the namespace provided.  The first matching child
 *  is returned.
 *
 *  @param stanza a Strophe stanza object
 *  @param ns a string with the namespace to match
 *
 *  @return the matching child stanza object or NULL if no match was found
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_get_child_by_ns(xmpp_stanza_t *stanza,
                                           const char *ns)
{
    xmpp_stanza_t *child;
    const char *child_ns;

    for (child = stanza->children; child; child = child->next) {
        child_ns = xmpp_stanza_get_ns(child);
        if (child_ns && strcmp(ns, child_ns) == 0)
            break;
    }

    return child;
}

/** Get the first child of stanza with name and a given namespace.
 *  This function searches all the immediate children of stanza for a child
 *  stanza that matches the name and namespace provided.
 *  The first matching child is returned.
 *
 *  @param stanza a Strophe stanza object
 *  @param name a string with the name to match
 *  @param ns a string with the namespace to match
 *
 *  @return the matching child stanza object or NULL if no match was found
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_get_child_by_name_and_ns(xmpp_stanza_t *stanza,
                                                    const char *name,
                                                    const char *ns)
{
    xmpp_stanza_t *child;
    const char *child_ns;

    for (child = stanza->children; child; child = child->next) {
        if (child->type == XMPP_STANZA_TAG &&
            (strcmp(name, xmpp_stanza_get_name(child)) == 0)) {
            child_ns = xmpp_stanza_get_ns(child);
            if (child_ns && strcmp(ns, child_ns) == 0) {
                break;
            }
        }
    }

    return child;
}

/** Get the list of children.
 *  This function returns the first child of the stanza object.  The rest
 *  of the children can be obtained by calling xmpp_stanza_get_next() to
 *  iterate over the siblings.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return the first child stanza or NULL if there are no children
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_get_children(xmpp_stanza_t *stanza)
{
    return stanza->children;
}

/** Get the next sibling of a stanza.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return the next sibling stanza or NULL if there are no more siblings
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_get_next(xmpp_stanza_t *stanza)
{
    return stanza->next;
}

/** Get the text data for a text stanza.
 *  This function copies the text data from a stanza and returns the new
 *  allocated string.  The caller is responsible for freeing this string
 *  with xmpp_free().
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return an allocated string with the text data
 *
 *  @ingroup Stanza
 */
char *xmpp_stanza_get_text(xmpp_stanza_t *stanza)
{
    size_t len, clen;
    xmpp_stanza_t *child;
    char *text;

    if (stanza->type == XMPP_STANZA_TEXT) {
        if (stanza->data)
            return strophe_strdup(stanza->ctx, stanza->data);
        else
            return NULL;
    }

    len = 0;
    for (child = stanza->children; child; child = child->next)
        if (child->type == XMPP_STANZA_TEXT)
            len += strlen(child->data);

    if (len == 0)
        return NULL;

    text = (char *)strophe_alloc(stanza->ctx, len + 1);
    if (!text)
        return NULL;

    len = 0;
    for (child = stanza->children; child; child = child->next)
        if (child->type == XMPP_STANZA_TEXT) {
            clen = strlen(child->data);
            memcpy(&text[len], child->data, clen);
            len += clen;
        }

    text[len] = 0;

    return text;
}

/** Get the text data pointer for a text stanza.
 *  This function copies returns the raw pointer to the text data in the
 *  stanza.  This should only be used in very special cases where the
 *  caller needs to translate the datatype as this will save a double
 *  allocation.  The caller should not hold onto this pointer, and is
 *  responsible for allocating a copy if it needs one.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return an string pointer to the data or NULL
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_text_ptr(xmpp_stanza_t *stanza)
{
    if (stanza->type == XMPP_STANZA_TEXT)
        return stanza->data;
    return NULL;
}

/** Set the 'id' attribute of a stanza.
 *
 *  This is a convenience function for:
 *  xmpp_stanza_set_attribute(stanza, 'id', id);
 *
 *  @param stanza a Strophe stanza object
 *  @param id a string containing the 'id' value
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_id(xmpp_stanza_t *stanza, const char *id)
{
    return xmpp_stanza_set_attribute(stanza, "id", id);
}

/** Set the 'type' attribute of a stanza.
 *  This is a convenience function for:
 *  xmpp_stanza_set_attribute(stanza, 'type', type);
 *
 *  @param stanza a Strophe stanza object
 *  @param type a string containing the 'type' value
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_type(xmpp_stanza_t *stanza, const char *type)
{
    return xmpp_stanza_set_attribute(stanza, "type", type);
}

/** Set the 'to' attribute of a stanza.
 *
 *  This is a convenience function for:
 *  xmpp_stanza_set_attribute(stanza, 'to', to);
 *
 *  @param stanza a Strophe stanza object
 *  @param to a string containing the 'to' value
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_to(xmpp_stanza_t *stanza, const char *to)
{
    return xmpp_stanza_set_attribute(stanza, "to", to);
}

/** Set the 'from' attribute of a stanza.
 *
 *  This is a convenience function for:
 *  xmpp_stanza_set_attribute(stanza, 'from', from);
 *
 *  @param stanza a Strophe stanza object
 *  @param from a string containing the 'from' value
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_set_from(xmpp_stanza_t *stanza, const char *from)
{
    return xmpp_stanza_set_attribute(stanza, "from", from);
}

/** Get an attribute from a stanza.
 *  This function returns a pointer to the attribute value.  If the caller
 *  wishes to save this value it must make its own copy.
 *
 *  @param stanza a Strophe stanza object
 *  @param name a string containing attribute name
 *
 *  @return a string with the attribute value or NULL on an error
 *
 *  @ingroup Stanza
 */
const char *xmpp_stanza_get_attribute(xmpp_stanza_t *stanza, const char *name)
{
    if (stanza->type != XMPP_STANZA_TAG)
        return NULL;

    if (!stanza->attributes)
        return NULL;

    return hash_get(stanza->attributes, name);
}

/** Delete an attribute from a stanza.
 *
 *  @param stanza a Strophe stanza object
 *  @param name a string containing attribute name
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Stanza
 */
int xmpp_stanza_del_attribute(xmpp_stanza_t *stanza, const char *name)
{
    if (stanza->type != XMPP_STANZA_TAG)
        return -1;

    if (!stanza->attributes)
        return -1;

    return hash_drop(stanza->attributes, name);
}

/** Create a stanza object in reply to another.
 *  This function makes a copy of a stanza object with the attribute "to" set
 *  its original "from".
 *  The stanza will have a reference count of one, so the caller does not
 *  need to clone it.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_reply(xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *copy = NULL;
    const char *from;
    int rc;

    from = xmpp_stanza_get_from(stanza);
    if (!from)
        goto copy_error;

    copy = xmpp_stanza_new(stanza->ctx);
    if (!copy)
        goto copy_error;

    copy->type = stanza->type;

    if (stanza->data) {
        copy->data = strophe_strdup(stanza->ctx, stanza->data);
        if (!copy->data)
            goto copy_error;
    }

    if (stanza->attributes) {
        if (_stanza_copy_attributes(copy, stanza) < 0)
            goto copy_error;
    }

    xmpp_stanza_del_attribute(copy, "to");
    xmpp_stanza_del_attribute(copy, "from");
    xmpp_stanza_del_attribute(copy, "xmlns");
    rc = xmpp_stanza_set_to(copy, from);
    if (rc != XMPP_EOK)
        goto copy_error;

    return copy;

copy_error:
    if (copy)
        xmpp_stanza_release(copy);
    return NULL;
}

/** Create an error stanza in reply to the provided stanza.
 *
 *  Check https://tools.ietf.org/html/rfc6120#section-8.3 for details.
 *
 *  @param stanza a Strophe stanza object
 *  @param error_type type attribute in the `<error/>` child element
 *  @param condition the defined-condition (e.g. "item-not-found")
 *  @param text optional description, may be NULL
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_reply_error(xmpp_stanza_t *stanza,
                                       const char *error_type,
                                       const char *condition,
                                       const char *text)
{
    xmpp_ctx_t *ctx = stanza->ctx;
    xmpp_stanza_t *reply = NULL;
    xmpp_stanza_t *error = NULL;
    xmpp_stanza_t *item = NULL;
    xmpp_stanza_t *text_stanza = NULL;
    const char *to;

    if (!error_type || !condition)
        goto quit_err;

    reply = xmpp_stanza_reply(stanza);
    if (!reply)
        goto quit_err;
    if (xmpp_stanza_set_type(reply, "error") != XMPP_EOK)
        goto quit_err;
    to = xmpp_stanza_get_to(stanza);
    if (to)
        if (xmpp_stanza_set_from(reply, to) != XMPP_EOK)
            goto quit_err;

    error = xmpp_stanza_new(ctx);
    if (!error)
        goto quit_err;
    if (xmpp_stanza_set_name(error, "error") != XMPP_EOK)
        goto quit_err;
    if (xmpp_stanza_set_type(error, error_type) != XMPP_EOK)
        goto quit_err;
    if (xmpp_stanza_add_child(reply, error) != XMPP_EOK)
        goto quit_err;
    xmpp_stanza_release(error);

    item = xmpp_stanza_new(ctx);
    if (!item)
        goto quit_err;
    if (xmpp_stanza_set_name(item, condition) != XMPP_EOK)
        goto quit_err;
    if (xmpp_stanza_set_ns(item, XMPP_NS_STANZAS_IETF) != XMPP_EOK)
        goto quit_err;
    if (xmpp_stanza_add_child(error, item) != XMPP_EOK)
        goto quit_err;
    xmpp_stanza_release(item);

    if (text) {
        item = xmpp_stanza_new(ctx);
        if (!item)
            goto quit_err;
        if (xmpp_stanza_set_name(item, "text") != XMPP_EOK)
            goto quit_err;
        if (xmpp_stanza_set_ns(item, XMPP_NS_STANZAS_IETF) != XMPP_EOK)
            goto quit_err;
        if (xmpp_stanza_add_child(error, item) != XMPP_EOK)
            goto quit_err;
        xmpp_stanza_release(item);
        text_stanza = xmpp_stanza_new(ctx);
        if (!text_stanza)
            goto quit_err;
        if (xmpp_stanza_set_text(text_stanza, text) != XMPP_EOK)
            goto quit_err;
        if (xmpp_stanza_add_child(item, text_stanza) != XMPP_EOK)
            goto quit_err;
        xmpp_stanza_release(text_stanza);
    }

    return reply;

quit_err:
    if (reply)
        xmpp_stanza_release(reply);
    if (error)
        xmpp_stanza_release(error);
    if (item)
        xmpp_stanza_release(item);
    if (text_stanza)
        xmpp_stanza_release(text_stanza);
    return NULL;
}

static xmpp_stanza_t *_stanza_new_with_attrs(xmpp_ctx_t *ctx,
                                             const char *name,
                                             const char *type,
                                             const char *id,
                                             const char *to)
{
    xmpp_stanza_t *stanza = xmpp_stanza_new(ctx);
    int ret;

    if (stanza) {
        ret = xmpp_stanza_set_name(stanza, name);
        if (ret == XMPP_EOK && type)
            ret = xmpp_stanza_set_type(stanza, type);
        if (ret == XMPP_EOK && id)
            ret = xmpp_stanza_set_id(stanza, id);
        if (ret == XMPP_EOK && to)
            ret = xmpp_stanza_set_to(stanza, to);
        if (ret != XMPP_EOK) {
            xmpp_stanza_release(stanza);
            stanza = NULL;
        }
    }
    return stanza;
}

/** Create a `<message/>` stanza object with given attributes.
 *  Attributes are optional and may be NULL.
 *
 *  @param ctx a Strophe context object
 *  @param type attribute 'type'
 *  @param to attribute 'to'
 *  @param id attribute 'id'
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_message_new(xmpp_ctx_t *ctx,
                                const char *type,
                                const char *to,
                                const char *id)
{
    return _stanza_new_with_attrs(ctx, "message", type, id, to);
}

/** Get text from `<body/>` child element.
 *  This function returns new allocated string. The caller is responsible
 *  for freeing this string with xmpp_free().
 *
 *  @param msg well formed `<message/>` stanza
 *
 *  @return allocated string or NULL on failure (no `<body/>` element or
 *      memory allocation error)
 *
 *  @ingroup Stanza
 */
char *xmpp_message_get_body(xmpp_stanza_t *msg)
{
    xmpp_stanza_t *body;
    const char *name;
    char *text = NULL;

    name = xmpp_stanza_get_name(msg);
    body = xmpp_stanza_get_child_by_name(msg, "body");
    if (name && strcmp(name, "message") == 0 && body) {
        text = xmpp_stanza_get_text(body);
    }
    return text;
}

/** Add `<body/>` child element to a `<message/>` stanza with the given text.
 *
 *  @param msg a `<message>` stanza object without `<body/>` child element.
 *  @param text The text that shall be placed in the body.
 *
 *  @return 0 on success (XMPP_EOK), and a number less than 0 on failure
 *      (XMPP_EMEM, XMPP_EINVOP)
 *
 *  @ingroup Stanza
 */
int xmpp_message_set_body(xmpp_stanza_t *msg, const char *text)
{
    xmpp_ctx_t *ctx = msg->ctx;
    xmpp_stanza_t *body;
    xmpp_stanza_t *text_stanza;
    const char *name;
    int ret;

    /* check that msg is a `<message/>` stanza and doesn't contain `<body/>` */
    name = xmpp_stanza_get_name(msg);
    body = xmpp_stanza_get_child_by_name(msg, "body");
    if (!name || strcmp(name, "message") != 0 || body)
        return XMPP_EINVOP;

    body = xmpp_stanza_new(ctx);
    text_stanza = xmpp_stanza_new(ctx);

    ret = body && text_stanza ? XMPP_EOK : XMPP_EMEM;
    if (ret == XMPP_EOK)
        ret = xmpp_stanza_set_name(body, "body");
    if (ret == XMPP_EOK)
        ret = xmpp_stanza_set_text(text_stanza, text);
    if (ret == XMPP_EOK)
        ret = xmpp_stanza_add_child(body, text_stanza);
    if (ret == XMPP_EOK)
        ret = xmpp_stanza_add_child(msg, body);

    if (text_stanza)
        xmpp_stanza_release(text_stanza);
    if (body)
        xmpp_stanza_release(body);

    return ret;
}

/** Create an `<iq/>` stanza object with given attributes.
 *  Attributes are optional and may be NULL.
 *
 *  @param ctx a Strophe context object
 *  @param type attribute 'type'
 *  @param id attribute 'id'
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_iq_new(xmpp_ctx_t *ctx, const char *type, const char *id)
{
    return _stanza_new_with_attrs(ctx, "iq", type, id, NULL);
}

/** Create a `<presence/>` stanza object.
 *
 *  @param ctx a Strophe context object
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_presence_new(xmpp_ctx_t *ctx)
{
    return _stanza_new_with_attrs(ctx, "presence", NULL, NULL, NULL);
}

/** Create an <stream:error/> stanza object with given type and error text.
 *  The error text is optional and may be NULL.
 *
 *  @param ctx a Strophe context object
 *  @param type enum of strophe_error_type_t
 *  @param text content of a 'text'
 *
 *  @return a new Strophe stanza object
 *
 *  @todo Handle errors in this function
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *
xmpp_error_new(xmpp_ctx_t *ctx, xmpp_error_type_t type, const char *text)
{
    xmpp_stanza_t *error =
        _stanza_new_with_attrs(ctx, "stream:error", NULL, NULL, NULL);
    xmpp_stanza_t *error_type = xmpp_stanza_new(ctx);

    switch (type) {
    case XMPP_SE_BAD_FORMAT:
        xmpp_stanza_set_name(error_type, "bad-format");
        break;
    case XMPP_SE_BAD_NS_PREFIX:
        xmpp_stanza_set_name(error_type, "bad-namespace-prefix");
        break;
    case XMPP_SE_CONFLICT:
        xmpp_stanza_set_name(error_type, "conflict");
        break;
    case XMPP_SE_CONN_TIMEOUT:
        xmpp_stanza_set_name(error_type, "connection-timeout");
        break;
    case XMPP_SE_HOST_GONE:
        xmpp_stanza_set_name(error_type, "host-gone");
        break;
    case XMPP_SE_HOST_UNKNOWN:
        xmpp_stanza_set_name(error_type, "host-unknown");
        break;
    case XMPP_SE_IMPROPER_ADDR:
        xmpp_stanza_set_name(error_type, "improper-addressing");
        break;
    case XMPP_SE_INTERNAL_SERVER_ERROR:
        xmpp_stanza_set_name(error_type, "internal-server-error");
        break;
    case XMPP_SE_INVALID_FROM:
        xmpp_stanza_set_name(error_type, "invalid-from");
        break;
    case XMPP_SE_INVALID_ID:
        xmpp_stanza_set_name(error_type, "invalid-id");
        break;
    case XMPP_SE_INVALID_NS:
        xmpp_stanza_set_name(error_type, "invalid-namespace");
        break;
    case XMPP_SE_INVALID_XML:
        xmpp_stanza_set_name(error_type, "invalid-xml");
        break;
    case XMPP_SE_NOT_AUTHORIZED:
        xmpp_stanza_set_name(error_type, "not-authorized");
        break;
    case XMPP_SE_POLICY_VIOLATION:
        xmpp_stanza_set_name(error_type, "policy-violation");
        break;
    case XMPP_SE_REMOTE_CONN_FAILED:
        xmpp_stanza_set_name(error_type, "remote-connection-failed");
        break;
    case XMPP_SE_RESOURCE_CONSTRAINT:
        xmpp_stanza_set_name(error_type, "resource-constraint");
        break;
    case XMPP_SE_RESTRICTED_XML:
        xmpp_stanza_set_name(error_type, "restricted-xml");
        break;
    case XMPP_SE_SEE_OTHER_HOST:
        xmpp_stanza_set_name(error_type, "see-other-host");
        break;
    case XMPP_SE_SYSTEM_SHUTDOWN:
        xmpp_stanza_set_name(error_type, "system-shutdown");
        break;
    case XMPP_SE_UNDEFINED_CONDITION:
        xmpp_stanza_set_name(error_type, "undefined-condition");
        break;
    case XMPP_SE_UNSUPPORTED_ENCODING:
        xmpp_stanza_set_name(error_type, "unsupported-encoding");
        break;
    case XMPP_SE_UNSUPPORTED_STANZA_TYPE:
        xmpp_stanza_set_name(error_type, "unsupported-stanza-type");
        break;
    case XMPP_SE_UNSUPPORTED_VERSION:
        xmpp_stanza_set_name(error_type, "unsupported-version");
        break;
    case XMPP_SE_XML_NOT_WELL_FORMED:
        xmpp_stanza_set_name(error_type, "xml-not-well-formed");
        break;
    default:
        xmpp_stanza_set_name(error_type, "internal-server-error");
        break;
    }

    xmpp_stanza_set_ns(error_type, XMPP_NS_STREAMS_IETF);
    xmpp_stanza_add_child_ex(error, error_type, 0);

    if (text) {
        xmpp_stanza_t *error_text = xmpp_stanza_new(ctx);
        xmpp_stanza_t *content = xmpp_stanza_new(ctx);

        xmpp_stanza_set_name(error_text, "text");
        xmpp_stanza_set_ns(error_text, XMPP_NS_STREAMS_IETF);

        xmpp_stanza_set_text(content, text);
        xmpp_stanza_add_child_ex(error_text, content, 0);

        xmpp_stanza_add_child_ex(error, error_text, 0);
    }

    return error;
}

static void _stub_stream_start(char *name, char **attrs, void *userdata)
{
    UNUSED(name);
    UNUSED(attrs);
    UNUSED(userdata);
}

static void _stub_stream_end(char *name, void *userdata)
{
    UNUSED(name);
    UNUSED(userdata);
}

static void _stream_stanza(xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t **dest = userdata;
    if (*dest == NULL) {
        stanza = xmpp_stanza_clone(stanza);
        *dest = stanza;
    }
}

/** Create a stanza object from the string.
 *  This function allocates and initializes a stanza object which represents
 *  stanza located in the string.
 *  The stanza will have a reference count of one, so the caller does not
 *  need to clone it.
 *
 *  @param ctx a Strophe context object
 *  @param str stanza in NULL terminated string representation
 *
 *  @return a stanza object or NULL on an error
 *
 *  @ingroup Stanza
 */
xmpp_stanza_t *xmpp_stanza_new_from_string(xmpp_ctx_t *ctx, const char *str)
{
    xmpp_stanza_t *stanza = NULL;
    parser_t *parser;
    int ret;

    static const char *start = "<stream>";
    static const char *end = "</stream>";

    parser = parser_new(ctx, _stub_stream_start, _stub_stream_end,
                        _stream_stanza, &stanza);
    if (parser) {
        ret = parser_feed(parser, (char *)start, strlen(start)) &&
              parser_feed(parser, (char *)str, strlen(str)) &&
              parser_feed(parser, (char *)end, strlen(end));
        parser_free(parser);
        if (!ret && stanza) {
            xmpp_stanza_release(stanza);
            stanza = NULL;
        }
    }
    return stanza;
}
