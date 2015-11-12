/* test.h
** libstrophe XMPP client library -- common routines for tests
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

#ifndef __LIBSTROPHE_TEST_H__
#define __LIBSTROPHE_TEST_H__

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ostypes.h"

#define TEST_MAIN                                           \
int main(int argc, char **argv) {                           \
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

#define COMPARE(v1, v2)            \
do {                               \
    const char *__v1 = v1;         \
    const char *__v2 = v2;         \
    if (strcmp(__v1, __v2) != 0) { \
        printf("%s differs!\n"     \
               "expected: %s\n"    \
               "got:      %s\n",   \
               #v1, __v1, __v2);   \
        exit(1);                   \
    }                              \
} while (0)

#define COMPARE_BUF(v1, len1, v2, len2)        \
do {                                           \
    const uint8_t *__v1 = (uint8_t *)(v1);     \
    const uint8_t *__v2 = (uint8_t *)(v2);     \
    size_t __len1 = len1;                      \
    size_t __len2 = len2;                      \
    if (__len1 != __len2 ||                    \
        memcmp(__v1, __v2, __len1) != 0)       \
    {                                          \
        printf("%s differs!\n", #v1);          \
        printf("expected: 0x%s\n",             \
               test_bin_to_hex(__v1, __len1)); \
        printf("got:      0x%s\n",             \
               test_bin_to_hex(__v2, __len2)); \
        exit(1);                               \
    }                                          \
} while (0)

void test_hex_to_bin(const char *hex, uint8_t *bin, size_t *bin_len);
const char *test_bin_to_hex(const uint8_t *bin, size_t len);

#endif /* __LIBSTROPHE_TEST_H__ */
