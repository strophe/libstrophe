AC_INIT([libstrophe], [0.8.5], [jack@metajack.im])
AM_INIT_AUTOMAKE([foreign])
LT_INIT([dlopen])

AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

AC_CANONICAL_HOST
AS_CASE([$host_os],
  [freebsd*], [PLATFORM="freebsd"],
  [PLATFORM="nix"])

PKG_CHECK_MODULES([openssl], [openssl], [], [AC_MSG_ERROR([openssl not found; openssl required])])
PKG_CHECK_MODULES([check], [check >= 0.9.4], [], [AC_MSG_WARN([libcheck not found; unit tests will not be compilable])])

AC_ARG_WITH([libxml2],
            [AS_HELP_STRING([--with-libxml2], [use libxml2 for XML parsing])],
            [with_libxml2=check],
            [with_libxml2=no])

if test "x$with_libxml2" != xno; then
  PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.7],
                    [with_libxml2=yes], [dummy=1])
  if test "x$with_libxml2" != xyes; then
    old_CFLAGS=$CFLAGS
    CFLAGS="-I${includedir}/libxml2"
    AC_CHECK_HEADER([libxml/parser.h],
                    [with_libxml2=yes; libxml2_CFLAGS="-I${includedir}/libxml2"; libxml2_LIBS="-lxml2"],
                    [AC_MSG_ERROR([libxml2 not found.])])
    CFLAGS=$old_CFLAGS
  fi
else
  PKG_CHECK_MODULES([expat], [expat >= 2.0.0], [],
                    [AC_CHECK_HEADER(expat.h, [expat_LIBS="-lexpat"], [AC_MSG_ERROR([expat not found; expat required.])])])
fi

if test "x$with_libxml2" = xyes; then
  with_parser=libxml2
  PARSER_NAME=libxml2
  PARSER_CFLAGS=$libxml2_CFLAGS
  PARSER_LIBS=$libxml2_LIBS
else
  with_parser=expat
  PARSER_NAME=expat
  PARSER_CFLAGS=$expat_CFLAGS
  PARSER_LIBS=$expat_LIBS
fi

AC_MSG_NOTICE([libstrophe will use the $with_parser XML parser])
AC_SEARCH_LIBS([socket], [socket])

if test "x$PLATFORM" != xfreebsd; then
        AC_CHECK_LIB([resolv], [res_query], [],
            [AC_CHECK_LIB([resolv], [__res_query], [],
                [AC_MSG_ERROR([libresolv not found; libresolv required. ])])])
else
        AC_MSG_NOTICE([skipping libresolv checks for freebsd])
fi

AC_CHECK_HEADERS([arpa/nameser_compat.h])

AM_CONDITIONAL([PARSER_EXPAT], [test x$with_parser != xlibxml2])
AC_SUBST(PARSER_NAME)
AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
