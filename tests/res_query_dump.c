/* Simple program to dump res_query(3) response. */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define STEP 8

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
        fprintf(stderr, "res_query(): Error occured (errno=%d)\n", errno);
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
            printf("\n");
        }
        printf("};\n");
    }

    return len <= 0;
}
