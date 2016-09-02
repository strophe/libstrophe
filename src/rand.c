/* rand.c
 * strophe XMPP client library -- pseudo-random number generator
 *
 * Copyright (C) 2014 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  Pseudo-random number generator.
 *
 *  Implemented Hash_DRBG mechanism according to NIST SP 800-90A.
 *  Hash function is SHA1.
 */

/** @defgroup Random Pseudo-random number generator
 */

#include <assert.h>
#include <string.h>     /* memeset */
#include <time.h>       /* clock, time */

#include "common.h"     /* xmpp_alloc, xmpp_free */
#include "ostypes.h"    /* uint8_t, uint32_t, size_t */
#include "sha1.h"
#include "snprintf.h"   /* xmpp_snprintf */

#include "rand.h"       /* xmpp_rand_t */

#define outlen SHA1_DIGEST_SIZE
#define seedlen (440 / 8)
#define reseed_interval 0x7fffffff

/* maximum number of bytes that can be generated per call */
#define GENERATE_MAX (outlen * 10)
#define ENTROPY_MAX 128
#define NONCE_MAX 8

#define RESEED_NEEDED (-1)

struct Hash_DRBG_CTX_struc {
    uint8_t V[seedlen];
    uint8_t C[seedlen];
    uint32_t reseed_counter;
};
typedef struct Hash_DRBG_CTX_struc Hash_DRBG_CTX;

struct _xmpp_rand_t {
    int inited;
    unsigned reseed_count;
    Hash_DRBG_CTX ctx;
};

/* returns smallest number mupliple of y that not less than x */
#define round_up(x, y) (((x) + (y) - 1) / (y) * (y))
/* returns smallest integer number that not less than x/y */
#define div_round_up(x, y) (((x) + (y) - 1) / (y))

/* adds two arrays as numbers in big-endian representation and stores
 * result in the first one.
 */
static void arr_add(uint8_t *arr1, size_t arr1_len,
                    uint8_t *arr2, size_t arr2_len)
{
    size_t i;
    uint32_t acc;
    uint32_t carry = 0;

    assert(arr1_len >= arr2_len);

    for (i = 1; (i <= arr2_len) || (carry != 0 && i <= arr1_len); ++i) {
        acc = (uint32_t)arr1[arr1_len - i] + carry;
        if (i <= arr2_len)
            acc += (uint32_t)arr2[arr2_len - i];
        carry = acc >> 8;
        arr1[arr1_len - i] = (uint8_t)(acc & 0xff);
    }
}

/* stores 32-bit number in big-endian representation */
static void store_be32(uint32_t val, uint8_t be[4])
{
    be[0] = (uint8_t)((val >> 24) & 0xff);
    be[1] = (uint8_t)((val >> 16) & 0xff);
    be[2] = (uint8_t)((val >> 8) & 0xff);
    be[3] = (uint8_t)(val & 0xff);
}

static void Hash_df(uint8_t *input_string, size_t input_string_len,
                    uint8_t *output_string, size_t no_of_bytes_to_return)
{
    uint8_t counter;
    uint8_t temp[round_up(seedlen, outlen)];
    uint8_t conj[ENTROPY_MAX + NONCE_MAX + seedlen + 6];
    size_t len;
    size_t i;
    size_t offset;

    assert(no_of_bytes_to_return <= sizeof(temp));
    assert(input_string_len + 5 <= sizeof(conj));

    len = div_round_up(no_of_bytes_to_return, outlen);
    for (i = 1; i <= len; ++i) {
        offset = (i - 1) * outlen;
        counter = (uint8_t)i;
        conj[0] = counter;
        store_be32((uint32_t)no_of_bytes_to_return * 8, conj + 1);
        memcpy(conj + 5, input_string, input_string_len);
        crypto_SHA1(conj, input_string_len + 5, temp + offset);
    }

    memcpy(output_string, temp, no_of_bytes_to_return);
}

/* assume personalization_string is zero length string */
static void Hash_DRBG_Instantiate(Hash_DRBG_CTX *ctx,
                                  uint8_t *entropy_input,
                                  size_t entropy_input_len,
                                  uint8_t *nonce, size_t nonce_len)
{
    uint8_t seed_material[ENTROPY_MAX + NONCE_MAX];
    uint8_t seed0[seedlen + 1];
    uint8_t *seed = seed0 + 1;

    assert(entropy_input_len <= ENTROPY_MAX);
    assert(nonce_len <= NONCE_MAX);

    memcpy(seed_material, entropy_input, entropy_input_len);
    memcpy(seed_material + entropy_input_len, nonce, nonce_len);
    Hash_df(seed_material, entropy_input_len + nonce_len, seed, seedlen);
    seed0[0] = 0;

    memcpy(ctx->V, seed, seedlen);
    Hash_df(seed0, sizeof(seed0), ctx->C, seedlen);
    ctx->reseed_counter = 1;
}

/* assume additional_input is zero length string */
static void Hash_DRBG_Reseed(Hash_DRBG_CTX *ctx,
                             uint8_t *entropy_input,
                             size_t entropy_input_len)
{
    uint8_t seed_material[1 + seedlen + ENTROPY_MAX];
    uint8_t seed0[seedlen + 1];
    uint8_t *seed = seed0 + 1;

    assert(entropy_input_len <= ENTROPY_MAX);

    seed_material[0] = 1;
    memcpy(seed_material + 1, ctx->V, seedlen);
    memcpy(seed_material + 1 + seedlen, entropy_input, entropy_input_len);
    Hash_df(seed_material, entropy_input_len + seedlen + 1, seed, seedlen);
    seed0[0] = 0;

    memcpy(ctx->V, seed, seedlen);
    Hash_df(seed0, sizeof(seed0), ctx->C, seedlen);
    ctx->reseed_counter = 1;
}

static void Hashgen(uint8_t *V, uint8_t *output,
                    size_t requested_number_of_bytes)
{
    uint8_t data[seedlen];
    uint8_t W[GENERATE_MAX];
    uint8_t i1 = 1;
    size_t m;
    size_t i;
    size_t offset;

    assert(requested_number_of_bytes <= sizeof(W));

    m = div_round_up(requested_number_of_bytes, outlen);
    memcpy(data, V, seedlen);
    for (i = 1; i <= m; ++i) {
        offset = (i - 1) * outlen;
        crypto_SHA1(data, seedlen, W + offset);
        /* increase data by 1 */
        arr_add(data, sizeof(data), &i1, 1);
    }

    memcpy(output, W, requested_number_of_bytes);
}

/* assume additional_input is zero length string */
static int Hash_DRBG_Generate(Hash_DRBG_CTX *ctx, uint8_t *output,
                              size_t requested_number_of_bytes)
{
    uint8_t H[outlen];
    uint8_t V3[seedlen + 1];
    uint8_t reseed_counter[4];

    if (ctx->reseed_counter > reseed_interval || ctx->reseed_counter == 0)
        return RESEED_NEEDED;

    Hashgen(ctx->V, output, requested_number_of_bytes);

    V3[0] = 3;
    memcpy(V3 + 1, ctx->V, seedlen);
    crypto_SHA1(V3, sizeof(V3), H);
    arr_add(ctx->V, sizeof(ctx->V), ctx->C, sizeof(ctx->C));
    arr_add(ctx->V, sizeof(ctx->V), H, sizeof(H));
    store_be32(ctx->reseed_counter, reseed_counter);
    arr_add(ctx->V, sizeof(ctx->V), reseed_counter, sizeof(reseed_counter));

    ++ctx->reseed_counter;
    return 0;
}

#define ENTROPY_ACCUMULATE(ptr, last, type, arg)    \
do {                                                \
    type __arg = (type)(arg);                       \
    if ((char*)ptr + sizeof(__arg) < (char*)last) { \
        *(type*)ptr = __arg;                        \
        ptr = (void*)((char*)ptr + sizeof(__arg));  \
    }                                               \
} while (0)

static void xmpp_rand_reseed(xmpp_rand_t *rand)
{
    uint8_t entropy[ENTROPY_MAX];
    uint8_t *ptr = entropy;
    const uint8_t *last = entropy + sizeof(entropy);
    size_t len;

    /* entropy:
     *  1. time_stamp()
     *  2. clock(3)
     *  3. xmpp_rand_t address to make unique seed within one process
     *  4. counter to make unique seed within one context
     *  5. stack address
     *  6. local ports of every connection in list (getsockname)
     *  7. other non-constant info that can be retieved from socket
     *
     *  rand(3) can't be used as it isn't thread-safe.
     *  XXX 6 and 7 are not implemented yet.
     */

    ENTROPY_ACCUMULATE(ptr, last, uint64_t, time_stamp());
    ENTROPY_ACCUMULATE(ptr, last, clock_t, clock());
    ENTROPY_ACCUMULATE(ptr, last, void *, rand);
    ENTROPY_ACCUMULATE(ptr, last, unsigned, ++rand->reseed_count);
    ENTROPY_ACCUMULATE(ptr, last, void *, &entropy);
    len = ptr - entropy;

    if (rand->inited) {
        Hash_DRBG_Reseed(&rand->ctx, entropy, len);
    } else {
        Hash_DRBG_Instantiate(&rand->ctx, entropy, len, NULL, 0);
        rand->inited = 1;
    }
}

xmpp_rand_t *xmpp_rand_new(xmpp_ctx_t *ctx)
{
    xmpp_rand_t *out = xmpp_alloc(ctx, sizeof(*out));
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    return out;
}

void xmpp_rand_free(xmpp_ctx_t *ctx, xmpp_rand_t *rand)
{
    xmpp_free(ctx, rand);
}

void xmpp_rand_bytes(xmpp_rand_t *rand, unsigned char *output, size_t len)
{
    int rc;

    rc = Hash_DRBG_Generate(&rand->ctx, (uint8_t *)output, len);
    if (rc == RESEED_NEEDED) {
        xmpp_rand_reseed(rand);
        rc = Hash_DRBG_Generate(&rand->ctx, (uint8_t *)output, len);
        assert(rc == 0);
    }
}

int xmpp_rand(xmpp_rand_t *rand)
{
    int result;

    xmpp_rand_bytes(rand, (unsigned char *)&result, sizeof(result));
    return result;
}

void xmpp_rand_nonce(xmpp_rand_t *rand, char *output, size_t len)
{
    size_t i;
    size_t rand_len = len / 2;
#ifndef _MSC_VER
    unsigned char rand_buf[rand_len];
#else
    unsigned char *rand_buf = (unsigned char *)_alloca(rand_len);
#endif

    /* current implementation returns printable HEX representation of
     * a random buffer, however base64 encoding can be used instead;
     * the only problem is that base64_encode() allocates memory and
     * as result can fail.
     */

    xmpp_rand_bytes(rand, rand_buf, rand_len);
    for (i = 0; i < rand_len; ++i) {
        xmpp_snprintf(output + i * 2, len, "%02x", rand_buf[i]);
        len -= 2;
    }
}
