/* sasl.c
** strophe XMPP client library -- SASL authentication helpers
** 
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

/** @file
 *  SASL authentication.
 */

#include <stdlib.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "ostypes.h"
#include "sasl.h"
#include "md5.h"
#include "sha1.h"
#include "scram.h"

#ifdef _WIN32
#define strtok_r strtok_s
#endif


/** generate authentication string for the SASL PLAIN mechanism */
char *sasl_plain(xmpp_ctx_t *ctx, const char *authid, const char *password) {
    int idlen, passlen;
    char *result = NULL;
    char *msg;
    
    /* our message is Base64(authzid,\0,authid,\0,password)
       if there is no authzid, that field is left empty */

    idlen = strlen(authid);
    passlen = strlen(password);
    msg = xmpp_alloc(ctx, 2 + idlen + passlen);
    if (msg != NULL) {
	msg[0] = '\0';
	memcpy(msg+1, authid, idlen);
	msg[1+idlen] = '\0';
	memcpy(msg+1+idlen+1, password, passlen);
	result = base64_encode(ctx, (unsigned char *)msg, 2 + idlen + passlen);
	xmpp_free(ctx, msg);
    }

    return result;
}

/** helpers for digest auth */

/* create a new, null-terminated string from a substring */
static char *_make_string(xmpp_ctx_t *ctx, const char *s, const unsigned len)
{
    char *result;

    result = xmpp_alloc(ctx, len + 1);
    if (result != NULL) {
	memcpy(result, s, len);
	result[len] = '\0';
    }
    return result;
}

/* create a new, null-terminated string quoting another string */
static char *_make_quoted(xmpp_ctx_t *ctx, const char *s)
{
    char *result;
    int len = strlen(s);

    result = xmpp_alloc(ctx, len + 3);
    if (result != NULL) {
	result[0] = '"';
	memcpy(result+1, s, len);
	result[len+1] = '"';
	result[len+2] = '\0';
    }
    return result;
}

/* split key, value pairs into a hash */
static hash_t *_parse_digest_challenge(xmpp_ctx_t *ctx, const char *msg)
{
    hash_t *result;
    unsigned char *text;
    char *key, *value;
    unsigned char *s, *t;

    text = base64_decode(ctx, msg, strlen(msg));
    if (text == NULL) {
	xmpp_error(ctx, "SASL", "couldn't Base64 decode challenge!");
	return NULL;
    }

    result = hash_new(ctx, 10, xmpp_free);
    if (result != NULL) {
	s = text;
	while (*s != '\0') {
	    /* skip any leading commas and spaces */
	    while ((*s == ',') || (*s == ' ')) s++;
	    /* accumulate a key ending at '=' */
	    t = s;
	    while ((*t != '=') && (*t != '\0')) t++;
	    if (*t == '\0') break; /* bad string */
	    key = _make_string(ctx, (char *)s, (t-s));
	    if (key == NULL) break;
            /* advance our start pointer past the key */
	    s = t + 1;
	    t = s;
	    /* if we see quotes, grab the string in between */
	    if ((*s == '\'') || (*s == '"')) {
		t++;
		while ((*t != *s) && (*t != '\0'))
		    t++;
		value = _make_string(ctx, (char *)s+1, (t-s-1));
		if (*t == *s) {
		    s = t + 1;
		} else {
		    s = t;
		}
	    /* otherwise, accumulate a value ending in ',' or '\0' */
	    } else {
		while ((*t != ',') && (*t != '\0')) t++;
		value = _make_string(ctx, (char *)s, (t-s));
		s = t;
	    }
	    if (value == NULL) {
		xmpp_free(ctx, key);
		break;
	    }
	    /* TODO: check for collisions per spec */
	    hash_add(result, key, value);
	    /* hash table now owns the value, free the key */
	    xmpp_free(ctx, key);
	}
    }
    xmpp_free(ctx, text);

    return result;
}

/** expand a 16 byte MD5 digest to a 32 byte hex representation */
static void _digest_to_hex(const char *digest, char *hex)
{
    int i;
    const char hexdigit[] = "0123456789abcdef";

    for (i = 0; i < 16; i++) {
	*hex++ = hexdigit[ (digest[i] >> 4) & 0x0F ];
	*hex++ = hexdigit[ digest[i] & 0x0F ];
    }
}

/** append 'key="value"' to a buffer, growing as necessary */
static char *_add_key(xmpp_ctx_t *ctx, hash_t *table, const char *key, 
		      char *buf, int *len, int quote)
{
    int olen,nlen;
    int keylen, valuelen;
    const char *value, *qvalue;
    char *c;

    /* allocate a zero-length string if necessary */
    if (buf == NULL) {
	buf = xmpp_alloc(ctx, 1);
	buf[0] = '\0';
    }
    if (buf == NULL) return NULL;

    /* get current string length */
    olen = strlen(buf);
    value = hash_get(table, key);
    if (value == NULL) {
	xmpp_error(ctx, "SASL", "couldn't retrieve value for '%s'", key);
	value = "";
    }
    if (quote) {
	qvalue = _make_quoted(ctx, value);
    } else {
	qvalue = value;
    }
    /* added length is key + '=' + value */
    /*   (+ ',' if we're not the first entry   */
    keylen = strlen(key);
    valuelen = strlen(qvalue);
    nlen = (olen ? 1 : 0) + keylen + 1 + valuelen + 1;
    buf = xmpp_realloc(ctx, buf, olen+nlen);

    if (buf != NULL) {
	c = buf + olen;
	if (olen) *c++ = ',';
	memcpy(c, key, keylen); c += keylen;
	*c++ = '=';
	memcpy(c, qvalue, valuelen); c += valuelen;
	*c++ = '\0';
    }

    if (quote) xmpp_free(ctx, (char *)qvalue);

    return buf;
}

/** generate auth response string for the SASL DIGEST-MD5 mechanism */
char *sasl_digest_md5(xmpp_ctx_t *ctx, const char *challenge,
			const char *jid, const char *password) {
    hash_t *table;
    char *result = NULL;
    char *node, *domain, *realm;
    char *value;
    char *response;
    int rlen;
    struct MD5Context MD5;
    unsigned char digest[16], HA1[16], HA2[16];
    char hex[32];

    /* our digest response is 
	Hex( KD( HEX(MD5(A1)),
	  nonce ':' nc ':' cnonce ':' qop ':' HEX(MD5(A2))
	))

       where KD(k, s) = MD5(k ':' s),
	A1 = MD5( node ':' realm ':' password ) ':' nonce ':' cnonce
	A2 = "AUTHENTICATE" ':' "xmpp/" domain

       If there is an authzid it is ':'-appended to A1 */

    /* parse the challenge */
    table = _parse_digest_challenge(ctx, challenge);
    if (table == NULL) {
	xmpp_error(ctx, "SASL", "couldn't parse digest challenge");
	return NULL;
    }

    node = xmpp_jid_node(ctx, jid);
    domain = xmpp_jid_domain(ctx, jid);

    /* generate default realm of domain if one didn't come from the
       server */
    realm = hash_get(table, "realm");
    if (realm == NULL || strlen(realm) == 0) {
	hash_add(table, "realm", xmpp_strdup(ctx, domain));
	realm = hash_get(table, "realm");
    }

    /* add our response fields */
    hash_add(table, "username", xmpp_strdup(ctx, node));
    /* TODO: generate a random cnonce */
    hash_add(table, "cnonce", xmpp_strdup(ctx, "00DEADBEEF00"));
    hash_add(table, "nc", xmpp_strdup(ctx, "00000001"));
    hash_add(table, "qop", xmpp_strdup(ctx, "auth"));
    value = xmpp_alloc(ctx, 5 + strlen(domain) + 1);
    memcpy(value, "xmpp/", 5);
    memcpy(value+5, domain, strlen(domain));
    value[5+strlen(domain)] = '\0';
    hash_add(table, "digest-uri", value);
    
    /* generate response */

    /* construct MD5(node : realm : password) */
    MD5Init(&MD5);
    MD5Update(&MD5, (unsigned char *)node, strlen(node));
    MD5Update(&MD5, (unsigned char *)":", 1);
    MD5Update(&MD5, (unsigned char *)realm, strlen(realm));
    MD5Update(&MD5, (unsigned char *)":", 1);
    MD5Update(&MD5, (unsigned char *)password, strlen(password));
    MD5Final(digest, &MD5);

    /* digest now contains the first field of A1 */

    MD5Init(&MD5);
    MD5Update(&MD5, digest, 16);
    MD5Update(&MD5, (unsigned char *)":", 1);
    value = hash_get(table, "nonce");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    MD5Update(&MD5, (unsigned char *)":", 1);
    value = hash_get(table, "cnonce");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    MD5Final(digest, &MD5);

    /* now digest is MD5(A1) */
    memcpy(HA1, digest, 16);

    /* construct MD5(A2) */
    MD5Init(&MD5);
    MD5Update(&MD5, (unsigned char *)"AUTHENTICATE:", 13);
    value = hash_get(table, "digest-uri");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    if (strcmp(hash_get(table, "qop"), "auth") != 0) {
	MD5Update(&MD5, (unsigned char *)":00000000000000000000000000000000",
		  33);
    }
    MD5Final(digest, &MD5);

    memcpy(HA2, digest, 16);

    /* construct response */
    MD5Init(&MD5);
    _digest_to_hex((char *)HA1, hex);
    MD5Update(&MD5, (unsigned char *)hex, 32);
    MD5Update(&MD5, (unsigned char *)":", 1);
    value = hash_get(table, "nonce");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    MD5Update(&MD5, (unsigned char *)":", 1);
    value = hash_get(table, "nc");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    MD5Update(&MD5, (unsigned char *)":", 1);
    value = hash_get(table, "cnonce");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    MD5Update(&MD5, (unsigned char *)":", 1);
    value = hash_get(table, "qop");
    MD5Update(&MD5, (unsigned char *)value, strlen(value));
    MD5Update(&MD5, (unsigned char *)":", 1);
    _digest_to_hex((char *)HA2, hex);
    MD5Update(&MD5, (unsigned char *)hex, 32);
    MD5Final(digest, &MD5);

    response = xmpp_alloc(ctx, 32+1);
    _digest_to_hex((char *)digest, hex);
    memcpy(response, hex, 32);
    response[32] = '\0';
    hash_add(table, "response", response);

    /* construct reply */
    result = NULL;
    rlen = 0;
    result = _add_key(ctx, table, "username", result, &rlen, 1); 
    result = _add_key(ctx, table, "realm", result, &rlen, 1); 
    result = _add_key(ctx, table, "nonce", result, &rlen, 1); 
    result = _add_key(ctx, table, "cnonce", result, &rlen, 1); 
    result = _add_key(ctx, table, "nc", result, &rlen, 0); 
    result = _add_key(ctx, table, "qop", result, &rlen, 0); 
    result = _add_key(ctx, table, "digest-uri", result, &rlen, 1); 
    result = _add_key(ctx, table, "response", result, &rlen, 0); 
    result = _add_key(ctx, table, "charset", result, &rlen, 0);
 
    xmpp_free(ctx, node);
    xmpp_free(ctx, domain);
    hash_release(table); /* also frees value strings */

    /* reuse response for the base64 encode of our result */
    response = base64_encode(ctx, (unsigned char *)result, strlen(result));
    xmpp_free(ctx, result);

    return response;
}

/** generate auth response string for the SASL SCRAM-SHA-1 mechanism */
char *sasl_scram_sha1(xmpp_ctx_t *ctx, const char *challenge,
                      const char *first_bare, const char *jid,
                      const char *password)
{
    uint8_t key[SHA1_DIGEST_SIZE];
    uint8_t sign[SHA1_DIGEST_SIZE];
    char *r = NULL;
    char *s = NULL;
    char *i = NULL;
    char *sval;
    size_t sval_len;
    long ival;
    char *tmp;
    char *ptr;
    char *saveptr = NULL;
    char *response;
    char *auth;
    char *response_b64;
    char *sign_b64;
    char *result = NULL;
    size_t response_len;
    size_t auth_len;
    int j;

    tmp = xmpp_strdup(ctx, challenge);
    if (!tmp) {
        return NULL;
    }

    ptr = strtok_r(tmp, ",", &saveptr);
    while (ptr) {
        if (strncmp(ptr, "r=", 2) == 0) {
            r = ptr;
        } else if (strncmp(ptr, "s=", 2) == 0) {
            s = ptr + 2;
        } else if (strncmp(ptr, "i=", 2) == 0) {
            i = ptr + 2;
        }
        ptr = strtok_r(NULL, ",", &saveptr);
    }

    if (!r || !s || !i) {
        goto out;
    }

    sval = (char *)base64_decode(ctx, s, strlen(s));
    if (!sval) {
        goto out;
    }
    sval_len = base64_decoded_len(ctx, s, strlen(s));
    ival = strtol(i, &saveptr, 10);

    auth_len = 10 + strlen(r) + strlen(first_bare) + strlen(challenge);
    auth = xmpp_alloc(ctx, auth_len);
    if (!auth) {
        goto out_sval;
    }

    response_len = 39 + strlen(r);
    response = xmpp_alloc(ctx, response_len);
    if (!response) {
        goto out_auth;
    }

    xmpp_snprintf(response, response_len, "c=biws,%s", r);
    xmpp_snprintf(auth, auth_len, "%s,%s,%s", first_bare + 3, challenge,
                  response);

    SCRAM_SHA1_ClientKey((uint8_t *)password, strlen(password),
                         (uint8_t *)sval, sval_len, (uint32_t)ival, key);
    SCRAM_SHA1_ClientSignature(key, (uint8_t *)auth, strlen(auth), sign);
    for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
        sign[j] ^= key[j];
    }

    sign_b64 = base64_encode(ctx, sign, sizeof(sign));
    if (!sign_b64) {
        goto out_response;
    }

    if (strlen(response) + strlen(sign_b64) + 3 + 1 > response_len) {
        xmpp_free(ctx, sign_b64);
        goto out_response;
    }
    strcat(response, ",p=");
    strcat(response, sign_b64);
    xmpp_free(ctx, sign_b64);

    response_b64 = base64_encode(ctx, (unsigned char *)response,
                                 strlen(response));
    if (!response_b64) {
        goto out_response;
    }
    result = response_b64;

out_response:
    xmpp_free(ctx, response);
out_auth:
    xmpp_free(ctx, auth);
out_sval:
    xmpp_free(ctx, sval);
out:
    xmpp_free(ctx, tmp);
    return result;
}


/** Base64 encoding routines. Implemented according to RFC 3548 */

/** map of all byte values to the base64 values, or to
    '65' which indicates an invalid character. '=' is '64' */
static const char _base64_invcharmap[256] = {
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

/** map of all 6-bit values to their corresponding byte
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

int base64_encoded_len(xmpp_ctx_t *ctx, const unsigned len)
{
    /* encoded steam is 4 bytes for every three, rounded up */
    return ((len + 2)/3) << 2;
}

char *base64_encode(xmpp_ctx_t *ctx, 
		    const unsigned char * const buffer, const unsigned len)
{
    int clen;
    char *cbuf, *c;
    uint32_t word, hextet;
    int i;

    clen = base64_encoded_len(ctx, len);
    cbuf = xmpp_alloc(ctx, clen + 1);
    if (cbuf != NULL) {
	c = cbuf;
	/* loop over data, turning every 3 bytes into 4 characters */
	for (i = 0; i < len - 2; i += 3) {
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

int base64_decoded_len(xmpp_ctx_t *ctx, 
		       const char * const buffer, const unsigned len)
{
    int nudge;
    int c;

    /* count the padding characters for the remainder */
    nudge = -1;
    c = _base64_invcharmap[(int)buffer[len-1]];
    if (c < 64) nudge = 0;
    else if (c == 64) {
	c = _base64_invcharmap[(int)buffer[len-2]];
	if (c < 64) nudge = 1;
	else if (c == 64) {
	    c = _base64_invcharmap[(int)buffer[len-3]];
	    if (c < 64) nudge = 2;
	} 
    }
    if (nudge < 0) return 0; /* reject bad coding */

    /* decoded steam is 3 bytes for every four */ 
    return 3 * (len >> 2) - nudge;
}

unsigned char *base64_decode(xmpp_ctx_t *ctx,
			     const char * const buffer, const unsigned len)
{
    int dlen;
    unsigned char *dbuf, *d;
    uint32_t word, hextet;
    int i;

    /* len must be a multiple of 4 */
    if (len & 0x03) return NULL;

    dlen = base64_decoded_len(ctx, buffer, len);
    dbuf = xmpp_alloc(ctx, dlen + 1);
    if (dbuf != NULL) {
	d = dbuf;
	/* loop over each set of 4 characters, decoding 3 bytes */
	for (i = 0; i < len - 3; i += 4) {
	    hextet = _base64_invcharmap[(int)buffer[i]];
	    if (hextet & 0xC0) break;
	    word = hextet << 18;
	    hextet = _base64_invcharmap[(int)buffer[i+1]];
	    if (hextet & 0xC0) break;
	    word |= hextet << 12;
	    hextet = _base64_invcharmap[(int)buffer[i+2]];
	    if (hextet & 0xC0) break;
	    word |= hextet << 6;
	    hextet = _base64_invcharmap[(int)buffer[i+3]];
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
		hextet = _base64_invcharmap[(int)buffer[len-4]];
		if (hextet & 0xC0) goto _base64_decode_error;
		word = hextet << 2;
		hextet = _base64_invcharmap[(int)buffer[len-3]];
		if (hextet & 0xC0) goto _base64_decode_error;
		word |= hextet >> 4;
		*d++ = word & 0xFF;
		hextet = _base64_invcharmap[(int)buffer[len-2]];
		if (hextet != 64) goto _base64_decode_error;
		hextet = _base64_invcharmap[(int)buffer[len-1]];
		if (hextet != 64) goto _base64_decode_error;
		break;
	    case 2:
		/* redo the last quartet, checking for correctness */
		hextet = _base64_invcharmap[(int)buffer[len-4]];
		if (hextet & 0xC0) goto _base64_decode_error;
		word = hextet << 10;		
		hextet = _base64_invcharmap[(int)buffer[len-3]];
		if (hextet & 0xC0) goto _base64_decode_error;
		word |= hextet << 4;		
		hextet = _base64_invcharmap[(int)buffer[len-2]];
		if (hextet & 0xC0) goto _base64_decode_error;
		word |= hextet >> 2;
		*d++ = (word & 0xFF00) >> 8;
		*d++ = (word & 0x00FF);		
		hextet = _base64_invcharmap[(int)buffer[len-1]];
		if (hextet != 64) goto _base64_decode_error;
		break;
	}
	*d = '\0';
    }
    return dbuf;

_base64_decode_error:	
    /* invalid character; abort decoding! */
    xmpp_free(ctx, dbuf);
    return NULL;
}

/*** self tests ***/
#ifdef TEST

#include <stdio.h>

int test_charmap_identity(void)
{
    int i, v, u;

    for (i = 0; i < 65; i++) {
	v = _base64_charmap[i];
	if (v > 255) return 1;
	u = _base64_invcharmap[v];
/*	printf("map: %d -> %d -> %d\n", i, v, u); */
	if (u != i) return 1;
    }

    return 0; 
}

int test_charmap_range(void)
{
    int i, v;

    for (i = 64; i < 256; i++) {
	v = _base64_invcharmap[i];
	if (i < 64) return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;

    printf("testing charmap identity...");
    ret = test_charmap_identity();
    if (ret) return ret;
    printf(" ok.\n");

    printf("testing charmap range...");
    ret = test_charmap_range();
    if (ret) return ret;
    printf(" ok.\n");

    printf("no error\n");
    return 0;
}

#endif /* TEST */
