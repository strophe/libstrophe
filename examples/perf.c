/* perf.c
 * strophe XMPP client library -- performance measure
 *
 * Copyright (C) 2022 Steffen Jaeckel <jaeckel-floss@eyet-services.de>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  performance measure
 *
 *  Timing code shamelessly borrowed from libtomcrypt/demos/timing.c
 */

#include <strophe.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

static void init_timer(void);
static void t_start(void);
static uint64_t t_read(void);

static void perf_rand(xmpp_ctx_t *ctx)
{
    xmpp_rand_t *rng = xmpp_rand_new(ctx);

    uint64_t t1, t2;
    unsigned int n;
    const size_t alloc_sz = 0x1000u;
    unsigned char *buf = malloc(alloc_sz);

    /* pre-heat */
    for (n = 1; n < 4; ++n) {
        xmpp_rand_bytes(rng, buf, n * 10);
    }

    for (size_t sz = 2; sz <= alloc_sz; sz <<= 1) {
        t2 = 0;
        for (n = 0; n < 1000u; ++n) {

            t_start();
            t1 = t_read();

            xmpp_rand_bytes(rng, buf, sz);

            t1 = t_read() - t1;
            t2 += t1;
        }
        t2 /= 1000;
        fprintf(stderr,
                "Reading %6zu bytes from PRNG took %8" PRIu64 " cycles\n", sz,
                t2);
    }
    free(buf);
    xmpp_rand_free(ctx, rng);
}

int main()
{
    /* pass NULL instead to silence output */
    xmpp_log_t *log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    /* create a context */
    xmpp_ctx_t *ctx = xmpp_ctx_new(NULL, log);

    init_timer();

    perf_rand(ctx);

    return 0;
}

#define TIMES 100000
static uint64_t timer, skew = 0;

/* RDTSC from Scott Duplichan */
static uint64_t rdtsc(void)
{
#if defined __GNUC__ && !defined(LTC_NO_ASM)
#if defined(__i386__) || defined(__x86_64__)
    /* version from http://www.mcs.anl.gov/~kazutomo/rdtsc.html
     * the old code always got a warning issued by gcc, clang did not
     * complain...
     */
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
#elif defined(LTC_PPC32) || defined(TFM_PPC32)
    unsigned long a, b;
    __asm__ __volatile__("mftbu %1 \nmftb %0\n" : "=r"(a), "=r"(b));
    return (((uint64_t)b) << 32ULL) | ((uint64_t)a);
#elif defined(__ia64__) /* gcc-IA64 version */
    unsigned long result;
    __asm__ __volatile__("mov %0=ar.itc" : "=r"(result)::"memory");
    while (__builtin_expect((int)result == -1, 0))
        __asm__ __volatile__("mov %0=ar.itc" : "=r"(result)::"memory");
    return result;
#elif defined(__sparc__)
#if defined(__arch64__)
    uint64_t a;
    asm volatile("rd %%tick,%0" : "=r"(a));
    return a;
#else
    register unsigned long x, y;
    __asm__ __volatile__("rd %%tick, %0; clruw %0, %1; srlx %0, 32, %0"
                         : "=r"(x), "=r"(y)
                         : "0"(x), "1"(y));
    return ((unsigned long long)x << 32) | y;
#endif
#elif defined(__aarch64__)
    uint64_t CNTVCT_EL0;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(CNTVCT_EL0));
    return CNTVCT_EL0;
#else
    return XCLOCK();
#endif

/* Microsoft and Intel Windows compilers */
#elif defined _M_IX86 && !defined(LTC_NO_ASM)
    __asm rdtsc
#elif defined _M_AMD64 && !defined(LTC_NO_ASM)
    return __rdtsc();
#elif defined _M_IA64 && !defined(LTC_NO_ASM)
#if defined __INTEL_COMPILER
#include <ia64intrin.h>
#endif
    return __getReg(3116);
#else
    return XCLOCK();
#endif
}

static void t_start(void)
{
    timer = rdtsc();
}

static uint64_t t_read(void)
{
    return rdtsc() - timer;
}

static void init_timer(void)
{
    uint64_t c1, c2, t1, t2;
    unsigned long y1;

    c1 = c2 = (uint64_t)-1;
    for (y1 = 0; y1 < TIMES * 100; y1++) {
        t_start();
        t1 = t_read();
        t2 = (t_read() - t1) >> 1;

        c1 = (t1 > c1) ? t1 : c1;
        c2 = (t2 > c2) ? t2 : c2;
    }
    skew = c2 - c1;
    fprintf(stderr, "Clock Skew: %lu\n", (unsigned long)skew);
}
