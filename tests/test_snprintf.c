/*
 * Copyright Patrick Powell 1995
 * This code is based on code written by Patrick Powell (papowell@astart.com)
 * It may be used for any purpose as long as this notice remains intact
 * on all source code distributions
 */

#include <stdio.h>
#include <string.h>

#undef HAVE_VSNPRINTF
#undef HAVE_SNPRINTF
#include "snprintf.c"

#ifndef LONG_STRING
#define LONG_STRING 1024
#endif

int main (void)
{
  char buf1[LONG_STRING];
  char buf2[LONG_STRING];
  char *fp_fmt[] = {
    "%-1.5f",
    "%1.5f",
    "%123.9f",
    "%10.5f",
    "% 10.5f",
    "%+22.9f",
    "%+4.9f",
    "%01.3f",
    "%4f",
    "%3.1f",
    "%3.2f",
    "%.0f",
    "%.1f",
    NULL
  };
  double fp_nums[] = { -1.5, 134.21, 91340.2, 341.1234, 0203.9, 0.96, 0.996,
    0.9996, 1.996, 4.136, 0};
  char *int_fmt[] = {
    "%-1.5d",
    "%1.5d",
    "%123.9d",
    "%5.5d",
    "%10.5d",
    "% 10.5d",
    "%+22.33d",
    "%01.3d",
    "%4d",
    "0x%x",
    "0x%04x",
    NULL
  };
  long int_nums[] = { -1, 134, 91340, 341, 0203, 0x76543210, 0};
  int x, y;
  int fail = 0;
  int num = 0;

  printf ("Testing xmpp_snprintf format codes against system sprintf...\n");

  for (x = 0; fp_fmt[x] != NULL ; x++)
    for (y = 0; fp_nums[y] != 0 ; y++)
    {
      xmpp_snprintf (buf1, sizeof (buf1), fp_fmt[x], fp_nums[y]);
      sprintf (buf2, fp_fmt[x], fp_nums[y]);
      if (strcmp (buf1, buf2))
      {
	printf("xmpp_snprintf doesn't match Format: %s\n\txmpp_snprintf = %s\n\tsprintf  = %s\n",
	    fp_fmt[x], buf1, buf2);
	fail++;
      }
      num++;
    }

  for (x = 0; int_fmt[x] != NULL ; x++)
    for (y = 0; int_nums[y] != 0 ; y++)
    {
      xmpp_snprintf (buf1, sizeof (buf1), int_fmt[x], int_nums[y]);
      sprintf (buf2, int_fmt[x], int_nums[y]);
      if (strcmp (buf1, buf2))
      {
	printf("xmpp_snprintf doesn't match Format: %s\n\txmpp_snprintf = %s\n\tsprintf  = %s\n",
	    int_fmt[x], buf1, buf2);
	fail++;
      }
      num++;
    }
  printf ("%d tests failed out of %d.\n", fail, num);
  return fail != 0 ? 1 : 0;
}
