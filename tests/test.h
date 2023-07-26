/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* test.h
** libstrophe XMPP client library -- common routines for tests
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

#ifndef __LIBSTROPHE_TEST_H__
#define __LIBSTROPHE_TEST_H__

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ostypes.h"

#define TEST_MAIN                                               \
    int main(int argc, char **argv)                             \
    {                                                           \
        int num_failed;                                         \
        Suite *s = parser_suite();                              \
        SRunner *sr = srunner_create(s);                        \
        srunner_run_all(sr, CK_NORMAL);                         \
        num_failed = srunner_ntests_failed(sr);                 \
        srunner_free(sr);                                       \
        return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE; \
    }

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define COMPARE(should, is)                                             \
    do {                                                                \
        const char *__should = should;                                  \
        const char *__is = is;                                          \
        if ((__should == NULL) && (__is == NULL)) {                     \
            /* noop */                                                  \
        } else if (!__should || !__is || strcmp(__should, __is) != 0) { \
            printf("Error:    %s\n"                                     \
                   "Expected: %s\n"                                     \
                   "Got:      %s\n",                                    \
                   #should " != " #is, __should, __is);                 \
            exit(1);                                                    \
        }                                                               \
    } while (0)

#define COMPARE_BUF(should, should_len, is, is_len)                      \
    do {                                                                 \
        const uint8_t *__should = (uint8_t *)(should);                   \
        const uint8_t *__is = (uint8_t *)(is);                           \
        size_t __should_len = should_len;                                \
        size_t __is_len = is_len;                                        \
        if (__should_len != __is_len ||                                  \
            memcmp(__should, __is, __should_len) != 0) {                 \
            printf("Error:    %s\n", #should " != " #is);                \
            printf("Expected: 0x%s\n",                                   \
                   test_bin_to_hex(__should, __should_len));             \
            printf("Got:      0x%s\n", test_bin_to_hex(__is, __is_len)); \
            exit(1);                                                     \
        }                                                                \
    } while (0)

#define ENSURE_EQ(should, is)                           \
    do {                                                \
        int __should = should;                          \
        int __is = is;                                  \
        if (__should != __is) {                         \
            printf("Error:    %s\n"                     \
                   "Expected: %d\n"                     \
                   "Got:      %d\n",                    \
                   #should " != " #is, __is, __should); \
            exit(1);                                    \
        }                                               \
    } while (0)

void test_hex_to_bin(const char *hex, uint8_t *bin, size_t *bin_len);
const char *test_bin_to_hex(const uint8_t *bin, size_t len);

#endif /* __LIBSTROPHE_TEST_H__ */
