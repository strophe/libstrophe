/* stanza.c
** libstrophe XMPP client library -- XMPP stanza object and utilities
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
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "hash.h"

#ifdef _WIN32
#define inline __inline
#endif

/* allocate an initialize a blank stanza */
xmpp_stanza_t *xmpp_stanza_new(xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *stanza;

    stanza = xmpp_alloc(ctx, sizeof(xmpp_stanza_t));
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

/* clone a stanza */
xmpp_stanza_t *xmpp_stanza_clone(xmpp_stanza_t * const stanza)
{
    xmpp_stanza_t *child;

    stanza->ref++;

    /* clone all children */
    for (child = stanza->children; child; child = child->next)
	xmpp_stanza_clone(child);

    return stanza;
}

/* copies and stanza and all children
 * this function returns a new stanza copied from stanza.  the new
 * stanza will have no parent and no siblings.  the caller is given
 * a reference to this new stanza.  this function is used to extract
 * a child from one stanza for inclusion in another. */
xmpp_stanza_t *xmpp_stanza_copy(const xmpp_stanza_t * const stanza)
{
    xmpp_stanza_t *copy, *child, *copychild, *tail;
    hash_iterator_t *iter;
    const char *key;
    void *val;

    copy = xmpp_stanza_new(stanza->ctx);
    if (!copy) goto copy_error;

    copy->type = stanza->type;

    if (stanza->data) {
	copy->data = xmpp_strdup(stanza->ctx, stanza->data);
	if (!copy->data) goto copy_error;
    }

    if (stanza->attributes) {
	copy->attributes = hash_new(stanza->ctx, 8, xmpp_free);
	if (!copy->attributes) goto copy_error;
	iter = hash_iter_new(stanza->attributes);
	if (!iter) { printf("DEBUG HERE\n"); goto copy_error; }
	while ((key = hash_iter_next(iter))) {
	    val = xmpp_strdup(stanza->ctx,
			      (char *)hash_get(stanza->attributes, key));
	    if (!val) goto copy_error;
	    
	    if (hash_add(copy->attributes, key, val))
		goto copy_error;
	}
	hash_iter_release(iter);
    }

    tail = copy->children;
    for (child = stanza->children; child; child = child->next) {
	copychild = xmpp_stanza_copy(child);
	if (!copychild) goto copy_error;
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
    if (copy) xmpp_stanza_release(copy);
    return NULL;
}

/* free a stanza object and it's contents */
int xmpp_stanza_release(xmpp_stanza_t * const stanza)
{
    int released = 0;
    xmpp_stanza_t *child, *tchild;

    /* release all children */
    child = stanza->children;
    while (child) {
	tchild = child;
	child = child->next;
	xmpp_stanza_release(tchild);
    }

    /* release stanza */
    if (stanza->ref > 1)
	stanza->ref--;
    else {
	if (stanza->attributes) hash_release(stanza->attributes);
	if (stanza->data) xmpp_free(stanza->ctx, stanza->data);
	xmpp_free(stanza->ctx, stanza);
	released = 1;
    }

    return released;
}

/* small helper function */
static inline void _render_update(int *written, const int length,
			   const int lastwrite,
			   size_t *left, char **ptr)
{
    *written += lastwrite;

    if (*written > length) {
	*left = 0;
	*ptr = NULL;
    } else {
	*left -= lastwrite;
	*ptr = &(*ptr)[lastwrite];
    }
}

/* always returns number of bytes written or that would have been
 * written if the buffer was large enough
 * return values < 0 indicate some error occured,
 * and return values > buflen indicate buffer was not large enough
 */
static int _render_stanza_recursive(xmpp_stanza_t *stanza,
			     char * const buf, size_t const buflen)
{
    char *ptr = buf;
    size_t left = buflen;
    int ret, written;
    xmpp_stanza_t *child;
    hash_iterator_t *iter;
    const char *key;

    written = 0;

    if (stanza->type == XMPP_STANZA_UNKNOWN) return XMPP_EINVOP;

    if (stanza->type == XMPP_STANZA_TEXT) {
	if (!stanza->data) return XMPP_EINVOP;

	ret = xmpp_snprintf(ptr, left, "%s", stanza->data);
	if (ret < 0) return XMPP_EMEM;
	_render_update(&written, buflen, ret, &left, &ptr);
    } else { /* stanza->type == XMPP_STANZA_TAG */
	if (!stanza->data) return XMPP_EINVOP;

	/* write begining of tag and attributes */
	ret = xmpp_snprintf(ptr, left, "<%s", stanza->data);
	if (ret < 0) return XMPP_EMEM;
	_render_update(&written, buflen, ret, &left, &ptr);

	if (stanza->attributes && hash_num_keys(stanza->attributes) > 0) {
	    iter = hash_iter_new(stanza->attributes);
	    while ((key = hash_iter_next(iter))) {
		ret = xmpp_snprintf(ptr, left, " %s=\"%s\"", key,
			       (char *)hash_get(stanza->attributes, key));
		if (ret < 0) return XMPP_EMEM;
		_render_update(&written, buflen, ret, &left, &ptr);
	    }
	    hash_iter_release(iter);
	}

	if (!stanza->children) {
	    /* write end if singleton tag */
	    ret = xmpp_snprintf(ptr, left, "/>");
	    if (ret < 0) return XMPP_EMEM;
	    _render_update(&written, buflen, ret, &left, &ptr);
	} else {
	    /* this stanza has child stanzas */

	    /* write end of start tag */
	    ret = xmpp_snprintf(ptr, left, ">");
	    if (ret < 0) return XMPP_EMEM;
	    _render_update(&written, buflen, ret, &left, &ptr);
	    
	    /* iterate and recurse over child stanzas */
	    child = stanza->children;
	    while (child) {
		ret = _render_stanza_recursive(child, ptr, left);
		if (ret < 0) return ret;

		_render_update(&written, buflen, ret, &left, &ptr);

		child = child->next;
	    }

	    /* write end tag */
	    ret = xmpp_snprintf(ptr, left, "</%s>", stanza->data);
	    if (ret < 0) return XMPP_EMEM;
	    
	    _render_update(&written, buflen, ret, &left, &ptr);
	}
    }

    return written;
}

/* render a stanza to text 
 * a buffer is allocated big enough to hold the stanza 
 * and *buf = buffer.  the size of buffer filled with data
 * is returned in *buflen (does not include trailing \0).  
 * the returned buffer contains a trailing \0 so the result is
 * a valid string.
 */
int  xmpp_stanza_to_text(xmpp_stanza_t *stanza,
			 char ** const buf,
			 size_t * const buflen)
{
    char *buffer, *tmp;
    size_t length;
    int ret;

    /* allocate a default sized buffer and attempt to render */
    length = 1024;
    buffer = xmpp_alloc(stanza->ctx, length);
    if (!buffer) {
	*buf = NULL;
	*buflen = 0;
	return XMPP_EMEM;
    }

    ret = _render_stanza_recursive(stanza, buffer, length);
    if (ret < 0) return ret;

    if (ret > length - 1) {
	tmp = xmpp_realloc(stanza->ctx, buffer, ret + 1);
	if (!tmp) {
	    xmpp_free(stanza->ctx, buffer);
	    *buf = NULL;
	    *buflen = 0;
	    return XMPP_EMEM;
	}
	length = ret + 1;
	buffer = tmp;

	ret = _render_stanza_recursive(stanza, buffer, length);
	if (ret > length - 1) return XMPP_EMEM;
    }
    
    buffer[length - 1] = 0;

    *buf = buffer;
    *buflen = ret;

    return XMPP_EOK;
}

int xmpp_stanza_set_name(xmpp_stanza_t *stanza, 
			 const char * const name)
{
    if (stanza->type == XMPP_STANZA_TEXT) return XMPP_EINVOP;

    if (stanza->data) xmpp_free(stanza->ctx, stanza->data);

    stanza->type = XMPP_STANZA_TAG;
    stanza->data = xmpp_strdup(stanza->ctx, name);

    return XMPP_EOK;
}

char *xmpp_stanza_get_name(xmpp_stanza_t * const stanza)
{
    if (stanza->type == XMPP_STANZA_TEXT) return NULL;
    return stanza->data;
}

/* convinience function to copy attributes from the xml parser
 * callback into a stanza.  this replaces all previous attributes */
int xmpp_stanza_set_attributes(xmpp_stanza_t * const stanza,
			       const char * const * const attr)
{
    int i;
    char *value;

    if (stanza->attributes != NULL)
	hash_release(stanza->attributes);

    stanza->attributes = hash_new(stanza->ctx, 8, xmpp_free);
    if (!stanza->attributes) return XMPP_EMEM;
    
    for (i = 0; attr[i]; i += 2) {
	value = xmpp_strdup(stanza->ctx, attr[i + 1]);
	if (!value) {
	    /* FIXME: memory allocation error */
	    continue;
	}
	hash_add(stanza->attributes, attr[i], value);
    }
    
    return XMPP_EOK;
}

int xmpp_stanza_set_attribute(xmpp_stanza_t * const stanza,
			      const char * const key,
			      const char * const value)
{
    char *val;

    if (stanza->type != XMPP_STANZA_TAG) return XMPP_EINVOP;

    if (!stanza->attributes) {
	stanza->attributes = hash_new(stanza->ctx, 8, xmpp_free);
	if (!stanza->attributes) return XMPP_EMEM;
    }

    val = xmpp_strdup(stanza->ctx, value);
    if (!val) return XMPP_EMEM;

    hash_add(stanza->attributes, key, val);

    return XMPP_EOK;
}

int xmpp_stanza_set_ns(xmpp_stanza_t * const stanza,
		       const char * const ns)
{
    return xmpp_stanza_set_attribute(stanza, "xmlns", ns);
}

int xmpp_stanza_add_child(xmpp_stanza_t *stanza, xmpp_stanza_t *child)
{
    xmpp_stanza_t *s;

    /* get a reference to the child */
    xmpp_stanza_clone(child);

    child->parent = stanza;

    if (!stanza->children)
	stanza->children = child;
    else {
	s = stanza->children;
	while (s->next) s = s->next;
	s->next = child;
	child->prev = s;
    }

    return XMPP_EOK;
}

int xmpp_stanza_set_text(xmpp_stanza_t *stanza,
			 const char * const text)
{
    if (stanza->type == XMPP_STANZA_TAG) return XMPP_EINVOP;
    
    stanza->type = XMPP_STANZA_TEXT;

    if (stanza->data) xmpp_free(stanza->ctx, stanza->data);
    stanza->data = xmpp_strdup(stanza->ctx, text);

    return XMPP_EOK;
}

int xmpp_stanza_set_text_with_size(xmpp_stanza_t *stanza,
				   const char * const text,
				   const size_t size)
{
    if (stanza->type == XMPP_STANZA_TAG) return XMPP_EINVOP;

    stanza->type = XMPP_STANZA_TEXT;

    if (stanza->data) xmpp_free(stanza->ctx, stanza->data);
    stanza->data = xmpp_alloc(stanza->ctx, size + 1);
    if (!stanza->data) return XMPP_EMEM;

    memcpy(stanza->data, text, size);
    stanza->data[size] = 0;

    return XMPP_EOK;
}

char *xmpp_stanza_get_id(xmpp_stanza_t * const stanza)
{
    if (stanza->type != XMPP_STANZA_TAG)
	return NULL;

    if (!stanza->attributes)
	return NULL;

    return (char *)hash_get(stanza->attributes, "id");
}

char *xmpp_stanza_get_ns(xmpp_stanza_t * const stanza)
{
    if (stanza->type != XMPP_STANZA_TAG)
	return NULL;

    if (!stanza->attributes)
	return NULL;

    return (char *)hash_get(stanza->attributes, "xmlns");
}

char *xmpp_stanza_get_type(xmpp_stanza_t * const stanza)
{
    if (stanza->type != XMPP_STANZA_TAG)
	return NULL;
    
    if (!stanza->attributes)
	return NULL;

    return (char *)hash_get(stanza->attributes, "type");
}

xmpp_stanza_t *xmpp_stanza_get_child_by_name(xmpp_stanza_t * const stanza, 
					     const char * const name)
{
    xmpp_stanza_t *child;
    
    for (child = stanza->children; child; child = child->next) {
	if (child->type == XMPP_STANZA_TAG &&
	    (strcmp(name, xmpp_stanza_get_name(child)) == 0))
	    break;
    }

    return child;
}

xmpp_stanza_t *xmpp_stanza_get_children(xmpp_stanza_t * const stanza) 
{
    return stanza->children;
}

xmpp_stanza_t *xmpp_stanza_get_next(xmpp_stanza_t * const stanza)
{
    return stanza->next;
}

char *xmpp_stanza_get_text(xmpp_stanza_t * const stanza)
{
    size_t len, clen;
    xmpp_stanza_t *child;
    char *text;

    len = 0;
    for (child = stanza->children; child; child = child->next)
	if (child->type == XMPP_STANZA_TEXT)
	    len += strlen(child->data);

    text = (char *)xmpp_alloc(stanza->ctx, len + 1);
    if (!text) return NULL;

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

int xmpp_stanza_set_id(xmpp_stanza_t * const stanza,
		       const char * const id)
{
    return xmpp_stanza_set_attribute(stanza, "id", id);
}

int xmpp_stanza_set_type(xmpp_stanza_t * const stanza,
			 const char * const type)
{
    return xmpp_stanza_set_attribute(stanza, "type", type);
}

char *xmpp_stanza_get_attribute(xmpp_stanza_t * const stanza,
				const char * const name)
{
    if (stanza->type != XMPP_STANZA_TAG)
	return NULL;
    
    if (!stanza->attributes)
	return NULL;

    return hash_get(stanza->attributes, name);
}
