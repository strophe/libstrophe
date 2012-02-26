AC_INIT([libstrophe], [0.8-snapshot], [jack@metajack.im])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_CC_C_O

AC_CHECK_HEADER(openssl/ssl.h, [], [AC_MSG_ERROR([couldn't find openssl headers, openssl required])])
PKG_CHECK_MODULES([check], [check >= 0.9.4], [], [AC_MSG_WARN([libcheck not found; unit tests will not be compilable])])

AC_ARG_WITH([libxml2],
            [AS_HELP_STRING([--with-libxml2], [use libxml2 for XML parsing])],
            [with_libxml2=check],
            [with_libxml2=no])

if test "x$with_libxml2" != xno; then
  PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.7],
                    [with_libxml2=yes],
                    [AC_MSG_ERROR([couldn't find libxml2])])
else
  AC_CHECK_HEADER(expat.h, [], [AC_MSG_ERROR([couldn't find expat headers; expat required])])
fi

if test "x$with_libxml2" = xyes; then
  with_parser=libxml2
  PARSER_NAME=libxml2
  PARSER_CFLAGS=\$\(libxml2_CFLAGS\)
  PARSER_LIBS=\$\(libxml2_LIBS\)
else
  with_parser=expat
  PARSER_NAME=expat
  PARSER_CFLAGS=
  PARSER_LIBS=-lexpat
fi

AC_MSG_NOTICE([libstrophe will use the $with_parser XML parser])
AC_SEARCH_LIBS([socket], [socket])

AC_LINK_IFELSE([AC_LANG_CALL([#include <resolv.h>], [res_query])], [],[LIBS="$LIBS -lresolv"])

AC_CHECK_HEADERS([arpa/nameser_compat.h])

AM_CONDITIONAL([PARSER_EXPAT], [test x$with_parser != xlibxml2])
AC_SUBST(PARSER_NAME)
AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
