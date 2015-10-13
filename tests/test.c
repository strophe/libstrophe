/* test.c
 * strophe XMPP client library -- common routines for tests
 *
 * Copyright (C) 2014 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

#include <assert.h>
#include <string.h>

#include "test.h"

static uint8_t char_to_bin(char c)
{
    return c <= '9' ? (uint8_t)(c - '0') :
           c <= 'Z' ? (uint8_t)(c - 'A' + 10) :
                      (uint8_t)(c - 'a' + 10);
}

void test_hex_to_bin(const char *hex, uint8_t *bin, size_t *bin_len)
{
    size_t len = strlen(hex);
    size_t i;

    assert(len % 2 == 0);

    for (i = 0; i < len / 2; ++i) {
        bin[i] = char_to_bin(hex[i * 2]) * 16 + char_to_bin(hex[i * 2 + 1]);
    }
    *bin_len = len / 2;
}

const char *test_bin_to_hex(const uint8_t *bin, size_t len)
{
    static char buf[2048];
    size_t i;

    static const char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    assert(ARRAY_SIZE(buf) > len * 2);

    for (i = 0; i < len; ++i) {
        buf[i * 2] = hex[(bin[i] >> 4) & 0x0f];
        buf[i * 2 + 1] = hex[bin[i] & 0x0f];
    }
    buf[len * 2] = '\0';

    return buf;
}
