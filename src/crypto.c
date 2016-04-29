/* crypto.c
 * strophe XMPP client library -- public interface for digests, encodings
 *
 * Copyright (C) 2016 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  Public interface for digests and encodings used in XEPs.
 */

/** @defgroup Digests Message digests
 */

#include <assert.h>
#include <string.h>     /* memset, memcpy */

#include "common.h"     /* xmpp_alloc */
#include "ostypes.h"    /* uint8_t, size_t */
#include "sha1.h"
#include "snprintf.h"   /* xmpp_snprintf */
#include "strophe.h"    /* xmpp_ctx_t, xmpp_free */

struct _xmpp_sha1_t {
    xmpp_ctx_t *xmpp_ctx;
    SHA1_CTX ctx;
    uint8_t digest[SHA1_DIGEST_SIZE];
};

static char *digest_to_string(const uint8_t *digest, char *s, size_t len)
{
    int i;

    if (len < SHA1_DIGEST_SIZE * 2 + 1)
        return NULL;

    for (i = 0; i < SHA1_DIGEST_SIZE; ++i)
        xmpp_snprintf(s + i * 2, 3, "%02x", digest[i]);

    return s;
}

static char *digest_to_string_alloc(xmpp_ctx_t *ctx, const uint8_t *digest)
{
    char *s;
    size_t slen;

    slen = SHA1_DIGEST_SIZE * 2 + 1;
    s = xmpp_alloc(ctx, slen);
    if (s) {
        s = digest_to_string(digest, s, slen);
        assert(s != NULL);
    }
    return s;
}

/** Compute SHA1 message digest
 *  Returns an allocated string which represents SHA1 message digest in
 *  hexadecimal notation. The string must be freed with xmpp_free().
 *
 *  @param ctx a Strophe context object
 *  @param data buffer for digest computation
 *  @param len size of the data buffer
 *
 *  @return an allocated string or NULL on allocation error
 *
 *  @ingroup Digests
 */
char *xmpp_sha1(xmpp_ctx_t *ctx, const unsigned char *data, size_t len)
{
    uint8_t digest[SHA1_DIGEST_SIZE];

    crypto_SHA1((const uint8_t *)data, len, digest);
    return digest_to_string_alloc(ctx, digest);
}

/** Create new SHA1 object
 *
 *  @param ctx a Strophe context onject
 *
 *  @return new SHA1 object
 *
 *  @ingroup Digests
 */
xmpp_sha1_t *xmpp_sha1_new(xmpp_ctx_t *ctx)
{
    xmpp_sha1_t *sha1;

    sha1 = xmpp_alloc(ctx, sizeof(*sha1));
    if (sha1) {
        memset(sha1, 0, sizeof(*sha1));
        crypto_SHA1_Init(&sha1->ctx);
        sha1->xmpp_ctx = ctx;
    }
    return sha1;
}

/** Destroy SHA1 object
 *
 *  @param sha1 a SHA1 object
 *
 *  @ingroup Digests
 */
void xmpp_sha1_free(xmpp_sha1_t *sha1)
{
    xmpp_free(sha1->xmpp_ctx, sha1);
}

/** Update SHA1 context with the next portion of data
 *  Can be called repeatedly.
 *
 *  @param sha1 a SHA1 object
 *  @param data pointer to a buffer to be hashed
 *  @param len size of the data buffer
 *
 *  @ingroup Digests
 */
void xmpp_sha1_update(xmpp_sha1_t *sha1, const unsigned char *data, size_t len)
{
    crypto_SHA1_Update(&sha1->ctx, data, len);
}

/** Finish SHA1 computation
 *  Don't call xmpp_sha1_update() after this function. Retrieve resulting
 *  message digest with xmpp_sha1_to_string() or xmpp_sha1_to_digest().
 *
 *  @param sha1 a SHA1 object
 *
 *  @ingroup Digests
 */
void xmpp_sha1_final(xmpp_sha1_t *sha1)
{
    crypto_SHA1_Final(&sha1->ctx, sha1->digest);
}

/** Return message digest rendered as a string
 *  Stores the string to a user's buffer and returns the buffer. Call this
 *  function after xmpp_sha1_final().
 *
 *  @param sha1 a SHA1 object
 *  @param s output string
 *  @param slen size reserved for the string including '\0'
 *
 *  @return pointer s or NULL if resulting string is bigger than slen bytes
 *
 *  @ingroup Digests
 */
char *xmpp_sha1_to_string(xmpp_sha1_t *sha1, char *s, size_t slen)
{
    return digest_to_string(sha1->digest, s, slen);
}

/** Return message digest rendered as a string
 *  Returns an allocated string. Free the string using the Strophe context
 *  which is passed to xmpp_sha1_new(). Call this function after
 *  xmpp_sha1_final().
 *
 *  @param sha1 a SHA1 object
 *
 *  @return an allocated string
 *
 *  @ingroup Digests
 */
char *xmpp_sha1_to_string_alloc(xmpp_sha1_t *sha1)
{
    return digest_to_string_alloc(sha1->xmpp_ctx, sha1->digest);
}

/** Stores message digest to a user's buffer
 *
 *  @param sha1 a SHA1 object
 *  @param digest output buffer of XMPP_SHA1_DIGEST_SIZE bytes
 *
 *  @ingroup Digests
 */
void xmpp_sha1_to_digest(xmpp_sha1_t *sha1, unsigned char *digest)
{
    assert(SHA1_DIGEST_SIZE == XMPP_SHA1_DIGEST_SIZE);
    memcpy(digest, sha1->digest, SHA1_DIGEST_SIZE);
}
