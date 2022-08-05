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
#include <time.h>

static void init_timer(void);
static void t_start(void);
static uint64_t t_read(void);
static const char *perf_time_unit;

#define NUM_SAMPLES 1000u

static void perf_rand(xmpp_ctx_t *ctx)
{
    xmpp_rand_t *rng = xmpp_rand_new(ctx);

    uint64_t t1, t2, t3 = 0;
    unsigned int n;
    const size_t alloc_sz = 0x1000u;
    size_t sz;
    unsigned char *buf = malloc(alloc_sz);

    /* pre-heat */
    for (n = 1; n < 4; ++n) {
        xmpp_rand_bytes(rng, buf, alloc_sz / n);
    }

    for (sz = 2; sz <= alloc_sz; sz <<= 1) {
        t2 = 0;
        for (n = 0; n < NUM_SAMPLES; ++n) {

            t_start();
            t1 = t_read();

            xmpp_rand_bytes(rng, buf, sz);

            t1 = t_read() - t1;
            t2 += t1;
        }
        t2 /= NUM_SAMPLES;
        fprintf(stderr, "Reading %6zu bytes from PRNG took %8" PRIu64 " %s\n",
                sz, t2, perf_time_unit);
        if (t3) {
            double d3 = (double)t3, d2 = (double)t2;
            fprintf(stderr, "    +%.2f%%\n",
                    (d2 - d3) / ((d2 + d3) * 0.5) * 100.);
        }
        t3 = t2;
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
#if defined __GNUC__
#if defined(__i386__) || defined(__x86_64__)
    /* version from http://www.mcs.anl.gov/~kazutomo/rdtsc.html
     * the old code always got a warning issued by gcc, clang did not
     * complain...
     */
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
#elif defined(__POWERPC__)
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
#elif defined HAVE_CLOCK_GETTIME
#define USE_CLOCK_GETTIME
    struct timespec result;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &result);
    return result.tv_sec * 1000000000 + result.tv_nsec;
#else
    return clock();
#endif /* __GNUC__ */

/* Microsoft and Intel Windows compilers */
#elif defined _M_IX86
    __asm rdtsc
#elif defined _M_AMD64
    return __rdtsc();
#elif defined _M_IA64
#if defined __INTEL_COMPILER
#include <ia64intrin.h>
#endif
    return __getReg(3116);
#elif defined HAVE_CLOCK_GETTIME
#define USE_CLOCK_GETTIME
    struct timespec result;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &result);
    return result.tv_sec * 1000000000 + result.tv_nsec;
#else
    return clock();
#endif
}

#if defined USE_CLOCK_GETTIME
static const char *perf_time_unit = "ns";
#else
static const char *perf_time_unit = "cycles";
#endif

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
