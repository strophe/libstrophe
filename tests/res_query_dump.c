/* res_query_dump.c
 * Simple program to dump res_query(3) response
 *
 * Copyright (C) 2014 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/* Linux and OSX:
 *   gcc -o res_query_dump tests/res_query_dump.c -lresolv
 * *BSD:
 *   gcc -o res_query_dump tests/res_query_dump.c
 * QNX:
 *   gcc -o res_query_dump tests/res_query_dump.c -lsocket
 * Solaris:
 *   gcc -o res_query_dump tests/res_query_dump.c -lresolv -lsocket -lnsl
 */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef T_SRV
#define T_SRV 33
#endif /* T_SRV */
#ifndef C_IN
#define C_IN 1
#endif /* C_IN */

#define STEP 10

int main(int argc, char **argv)
{
    unsigned char buf[65536];
    char fulldomain[2048];
    char *service = "xmpp-client";
    char *proto = "tcp";
    char *domain = NULL;
    int len;
    int i;
    int j;

    if (argc < 2) {
        fprintf(stderr, "%s: argument missed\n", argc > 0 ? argv[0] : "$0");
        fprintf(stderr, "Usage: %s <domain>\n", argc > 0 ? argv[0] : "$0");
        return 1;
    }

    domain = argv[1];
    snprintf(fulldomain, sizeof(fulldomain), "_%s._%s.%s",
             service, proto, domain);
    errno = 0;
    len = res_query(fulldomain, C_IN, T_SRV, buf, sizeof(buf));

    if (len < 0) {
        fprintf(stderr, "res_query(): Error occurred (errno=%d)\n", errno);
    }
    if (len == 0) {
        fprintf(stderr, "res_query(): Empty result\n");
    }
    if (len > 0) {
        printf("/* res_query(\"%s\", C_IN, T_SRV, ...) */\n", fulldomain);
        printf("static const unsigned char data[] = {\n");
        for (i = 0; i < len; i += STEP) {
            printf("   ");
            for (j = i; j < len && j < i + STEP; ++j) {
                printf(" 0x%02x,", buf[j]);
            }
            for (j = len; j < i + STEP; ++j) {
                printf("      ");
            }
            printf("    // ");
            for (j = i; j < len && j < i + STEP; ++j) {
                printf("%c", isprint(buf[j]) ? buf[j] : '.');
            }
            printf("\n");
        }
        printf("};\n");
    }

    return len <= 0;
}
