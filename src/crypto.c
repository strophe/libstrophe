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

/** @defgroup Encodings Encodings
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


/* Base64 encoding routines. Implemented according to RFC 3548. */

/* map of all byte values to the base64 values, or to
   '65' which indicates an invalid character. '=' is '64' */
static const unsigned char _base64_invcharmap[256] = {
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,62, 65,65,65,63,
    52,53,54,55, 56,57,58,59, 60,61,65,65, 65,64,65,65,
    65, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,65, 65,65,65,65,
    65,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65,
    65,65,65,65, 65,65,65,65, 65,65,65,65, 65,65,65,65
};

/* map of all 6-bit values to their corresponding byte
   in the base64 alphabet. Padding char is the value '64' */
static const char _base64_charmap[65] = {
    'A','B','C','D', 'E','F','G','H',
    'I','J','K','L', 'M','N','O','P',
    'Q','R','S','T', 'U','V','W','X',
    'Y','Z','a','b', 'c','d','e','f',
    'g','h','i','j', 'k','l','m','n',
    'o','p','q','r', 's','t','u','v',
    'w','x','y','z', '0','1','2','3',
    '4','5','6','7', '8','9','+','/',
    '='
};

static size_t base64_encoded_len(const size_t len)
{
    /* encoded steam is 4 bytes for every three, rounded up */
    return ((len + 2)/3) << 2;
}

static char *base64_encode(xmpp_ctx_t *ctx,
                           const unsigned char * const buffer, const size_t len)
{
    size_t clen;
    char *cbuf, *c;
    uint32_t word, hextet;
    size_t i;

    clen = base64_encoded_len(len);
    cbuf = xmpp_alloc(ctx, clen + 1);
    if (cbuf != NULL) {
        c = cbuf;
        /* loop over data, turning every 3 bytes into 4 characters */
        for (i = 0; i + 2 < len; i += 3) {
            word = buffer[i] << 16 | buffer[i+1] << 8 | buffer[i+2];
            hextet = (word & 0x00FC0000) >> 18;
            *c++ = _base64_charmap[hextet];
            hextet = (word & 0x0003F000) >> 12;
            *c++ = _base64_charmap[hextet];
            hextet = (word & 0x00000FC0) >> 6;
            *c++ = _base64_charmap[hextet];
            hextet = (word & 0x000003F);
            *c++ = _base64_charmap[hextet];
        }
        /* zero, one or two bytes left */
        switch (len - i) {
            case 0:
                break;
            case 1:
                hextet = (buffer[len-1] & 0xFC) >> 2;
                *c++ = _base64_charmap[hextet];
                hextet = (buffer[len-1] & 0x03) << 4;
                *c++ = _base64_charmap[hextet];
                *c++ = _base64_charmap[64]; /* pad */
                *c++ = _base64_charmap[64]; /* pad */
                break;
            case 2:
                hextet = (buffer[len-2] & 0xFC) >> 2;
                *c++ = _base64_charmap[hextet];
                hextet = ((buffer[len-2] & 0x03) << 4) |
                         ((buffer[len-1] & 0xF0) >> 4);
                *c++ = _base64_charmap[hextet];
                hextet = (buffer[len-1] & 0x0F) << 2;
                *c++ = _base64_charmap[hextet];
                *c++ = _base64_charmap[64]; /* pad */
                break;
        }
        /* add a terminal null */
        *c = '\0';
    }
    return cbuf;
}

static size_t base64_decoded_len(const char * const buffer, const size_t len)
{
    size_t nudge = 0;
    unsigned char c;
    size_t i;

    if (len < 4) return 0;

    /* count the padding characters for the remainder */
    for (i = len; i > 0; --i) {
        c = _base64_invcharmap[(unsigned char)buffer[i-1]];
        if (c < 64) break;
        if (c == 64) ++nudge;
        if (c > 64) return 0;
    }
    if (nudge > 2) return 0;

    /* decoded steam is 3 bytes for every four */
    return 3 * (len >> 2) - nudge;
}

static void base64_decode(xmpp_ctx_t *ctx,
                          const char * const buffer, const size_t len,
                          unsigned char **out, size_t *outlen)
{
    size_t dlen;
    unsigned char *dbuf, *d;
    uint32_t word, hextet = 0;
    size_t i;

    /* len must be a multiple of 4 */
    if (len & 0x03) goto _base64_error;

    dlen = base64_decoded_len(buffer, len);
    if (dlen == 0) goto _base64_error;

    dbuf = xmpp_alloc(ctx, dlen + 1);
    if (dbuf != NULL) {
        d = dbuf;
        /* loop over each set of 4 characters, decoding 3 bytes */
        for (i = 0; i + 3 < len; i += 4) {
            hextet = _base64_invcharmap[(unsigned char)buffer[i]];
            if (hextet & 0xC0) break;
            word = hextet << 18;
            hextet = _base64_invcharmap[(unsigned char)buffer[i+1]];
            if (hextet & 0xC0) break;
            word |= hextet << 12;
            hextet = _base64_invcharmap[(unsigned char)buffer[i+2]];
            if (hextet & 0xC0) break;
            word |= hextet << 6;
            hextet = _base64_invcharmap[(unsigned char)buffer[i+3]];
            if (hextet & 0xC0) break;
            word |= hextet;
            *d++ = (word & 0x00FF0000) >> 16;
            *d++ = (word & 0x0000FF00) >> 8;
            *d++ = (word & 0x000000FF);
        }
        if (hextet > 64) goto _base64_decode_error;
        /* handle the remainder */
        switch (dlen % 3) {
            case 0:
                /* nothing to do */
                break;
            case 1:
                /* redo the last quartet, checking for correctness */
                hextet = _base64_invcharmap[(unsigned char)buffer[len-4]];
                if (hextet & 0xC0) goto _base64_decode_error;
                word = hextet << 2;
                hextet = _base64_invcharmap[(unsigned char)buffer[len-3]];
                if (hextet & 0xC0) goto _base64_decode_error;
                word |= hextet >> 4;
                *d++ = word & 0xFF;
                hextet = _base64_invcharmap[(unsigned char)buffer[len-2]];
                if (hextet != 64) goto _base64_decode_error;
                hextet = _base64_invcharmap[(unsigned char)buffer[len-1]];
                if (hextet != 64) goto _base64_decode_error;
                break;
            case 2:
                /* redo the last quartet, checking for correctness */
                hextet = _base64_invcharmap[(unsigned char)buffer[len-4]];
                if (hextet & 0xC0) goto _base64_decode_error;
                word = hextet << 10;
                hextet = _base64_invcharmap[(unsigned char)buffer[len-3]];
                if (hextet & 0xC0) goto _base64_decode_error;
                word |= hextet << 4;
                hextet = _base64_invcharmap[(unsigned char)buffer[len-2]];
                if (hextet & 0xC0) goto _base64_decode_error;
                word |= hextet >> 2;
                *d++ = (word & 0xFF00) >> 8;
                *d++ = (word & 0x00FF);
                hextet = _base64_invcharmap[(unsigned char)buffer[len-1]];
                if (hextet != 64) goto _base64_decode_error;
                break;
        }
        *d = '\0';
    }
    *out = dbuf;
    *outlen = dbuf == NULL ? 0 : dlen;
    return;

_base64_decode_error:
    /* invalid character; abort decoding! */
    xmpp_free(ctx, dbuf);
_base64_error:
    *out = NULL;
    *outlen = 0;
}

/** Base64 encoding routine
 *  Returns an allocated string which must be freed with xmpp_free().
 *
 *  @param ctx a Strophe context
 *  @param data buffer to encode
 *  @param len size of the data buffer
 *
 *  @return an allocated null-terminated string or NULL on error
 *
 *  @ingroup Encodings
 */
char *xmpp_base64_encode(xmpp_ctx_t *ctx, const unsigned char *data, size_t len)
{
    return base64_encode(ctx, data, len);
}

/** Base64 decoding routine
 *  Returns an allocated string which must be freed with xmpp_free(). User
 *  calls this function when the result must be a string. When decoded buffer
 *  contains '\0' NULL is returned.
 *
 *  @param ctx a Strophe context
 *  @param base64 encoded buffer
 *  @param len size of the buffer
 *
 *  @return an allocated null-terminated string or NULL on error
 *
 *  @ingroup Encodings
 */
char *xmpp_base64_decode_str(xmpp_ctx_t *ctx, const char *base64, size_t len)
{
    unsigned char *buf = NULL;
    size_t buflen;

    if (len == 0) {
        /* handle empty string */
        buf = xmpp_alloc(ctx, 1);
        if (buf)
            buf[0] = '\0';
        buflen = 0;
    } else {
        base64_decode(ctx, base64, len, &buf, &buflen);
    }
    if (buf) {
        if (buflen != strlen((char *)buf)) {
            xmpp_free(ctx, buf);
            buf = NULL;
        }
    }
    return (char *)buf;
}

/** Base64 decoding routine
 *  Returns an allocated buffer which must be freed with xmpp_free().
 *
 *  @param ctx a Strophe context
 *  @param base64 encoded buffer
 *  @param len size of the encoded buffer
 *  @param out allocated buffer is stored here
 *  @param outlen size of the allocated buffer
 *
 *  @note on an error the `*out` will be NULL
 *
 *  @ingroup Encodings
 */
void xmpp_base64_decode_bin(xmpp_ctx_t *ctx, const char *base64, size_t len,
                            unsigned char **out, size_t *outlen)
{
    base64_decode(ctx, base64, len, out, outlen);
}
