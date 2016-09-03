/* sasl.c
** strophe XMPP client library -- SASL authentication helpers
** 
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
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
#include "rand.h"
#include "util.h"

/* strtok_s() has appeared in visual studio 2005.
   Use own implementation for older versions. */
#ifdef _MSC_VER
# if (_MSC_VER >= 1400)
# define strtok_r strtok_s
# else
# define strtok_r xmpp_strtok_r
# endif
#endif /* _MSC_VER */


/** generate authentication string for the SASL PLAIN mechanism */
char *sasl_plain(xmpp_ctx_t *ctx, const char *authid, const char *password) {
    size_t idlen, passlen;
    size_t msglen;
    char *result = NULL;
    char *msg;
    
    /* our message is Base64(authzid,\0,authid,\0,password)
       if there is no authzid, that field is left empty */

    idlen = strlen(authid);
    passlen = strlen(password);
    msglen = 2 + idlen + passlen;
    msg = xmpp_alloc(ctx, msglen);
    if (msg != NULL) {
	msg[0] = '\0';
	memcpy(msg+1, authid, idlen);
	msg[1+idlen] = '\0';
	memcpy(msg+1+idlen+1, password, passlen);
	result = xmpp_base64_encode(ctx, (unsigned char *)msg, msglen);
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
    size_t len = strlen(s);

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

    text = (unsigned char *)xmpp_base64_decode_str(ctx, msg, strlen(msg));
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
    char cnonce[13];

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
    xmpp_rand_nonce(ctx->rand, cnonce, sizeof(cnonce));
    hash_add(table, "cnonce", xmpp_strdup(ctx, cnonce));
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
    response = xmpp_base64_encode(ctx, (unsigned char *)result, strlen(result));
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
    unsigned char *sval;
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

    xmpp_base64_decode_bin(ctx, s, strlen(s), &sval, &sval_len);
    if (!sval) {
        goto out;
    }
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

    sign_b64 = xmpp_base64_encode(ctx, sign, sizeof(sign));
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

    response_b64 = xmpp_base64_encode(ctx, (unsigned char *)response,
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
