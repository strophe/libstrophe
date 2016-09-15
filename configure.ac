AC_INIT([libstrophe], [0.9.1], [jack@metajack.im])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
LT_INIT([dlopen])

AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

AC_CANONICAL_HOST
AS_CASE([$host_os],
    [freebsd*],    [PLATFORM="bsd"],
    [openbsd*],    [PLATFORM="bsd"],
    [netbsd*],     [PLATFORM="bsd"],
    [*nto*|*qnx*], [PLATFORM="qnx"],
    [*solaris*],   [PLATFORM="solaris"],
    [*android*],   [PLATFORM="android"],
                   [PLATFORM="nix"])

AC_ARG_WITH([libxml2],
    [AS_HELP_STRING([--with-libxml2], [use libxml2 for XML parsing, expat is the default])])
AC_ARG_ENABLE([tls],
    [AS_HELP_STRING([--disable-tls], [disable TLS support])])

if test "x$enable_tls" != xno; then
    PKG_CHECK_MODULES([openssl], [openssl],
        [PC_REQUIRES="openssl ${PC_REQUIRES}"],
        [AC_CHECK_HEADER([openssl/ssl.h],
            [
                openssl_LIBS="-lssl -lcrypto"
                PC_LIBS="${openssl_LIBS} ${PC_LIBS}"
            ],
            [AC_MSG_ERROR([openssl not found; openssl required])]
        )])
fi

with_parser=""
if test "x$with_libxml2" != xyes; then
    PKG_CHECK_MODULES([expat], [expat >= 2.0.0],
        [
            with_parser="expat"
            PC_REQUIRES="expat ${PC_REQUIRES}"
        ],
        [AC_CHECK_HEADER([expat.h],
            [
                with_parser="expat"
                expat_LIBS="-lexpat"
                PC_LIBS="${expat_LIBS} ${PC_LIBS}"
            ])
        ])
fi
if test "x$with_libxml2" != xno -a "x$with_parser" = x; then
    PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.7],
        [
            with_parser="libxml2"
            PC_REQUIRES="libxml-2.0 ${PC_REQUIRES}"
        ],
        [
            old_CFLAGS=$CFLAGS
            CFLAGS="-I${includedir}/libxml2"
            AC_CHECK_HEADER([libxml/parser.h],
                [
                    with_parser="libxml2"
                    libxml2_CFLAGS="-I${includedir}/libxml2"
                    libxml2_LIBS="-lxml2"
                    PC_LIBS="${libxml2_LIBS} ${PC_LIBS}"
                    PC_CFLAGS="${libxml2_CFLAGS} ${PC_CFLAGS}"
                ])
            CFLAGS=$old_CFLAGS
        ])
fi

if test "x$with_parser" = xlibxml2; then
    PARSER_CFLAGS=$libxml2_CFLAGS
    PARSER_LIBS=$libxml2_LIBS
elif test "x$with_parser" = xexpat; then
    PARSER_CFLAGS=$expat_CFLAGS
    PARSER_LIBS=$expat_LIBS
else
    AC_MSG_ERROR([no XML parser was found, libstrophe requires expat or libxml2])
fi

AC_MSG_NOTICE([libstrophe will use the $with_parser XML parser])

AC_SEARCH_LIBS([socket], [socket])

AS_CASE([$PLATFORM],
    [bsd],     [RESOLV_LIBS=""],
    [qnx],     [RESOLV_LIBS="-lsocket"],
    [solaris], [RESOLV_LIBS="-lresolv -lsocket -lnsl"],
    [android], [RESOLV_LIBS=""],
               [RESOLV_LIBS="-lresolv"])

LIBS_TMP="${LIBS}"
LIBS="${RESOLV_LIBS}"
AC_LINK_IFELSE([AC_LANG_SOURCE([
        #include <sys/types.h>
        #include <netinet/in.h>
        #include <arpa/nameser.h>
        #include <resolv.h>
        #include <netdb.h>

        int main() {
            (void)res_query(NULL, 0, 0, NULL, 0);
            return 0;
        }
    ])],
    [],
    [AC_MSG_ERROR([res_query() not found with LIBS="${LIBS}"])])
LIBS="${LIBS_TMP}"
PC_LIBS="${RESOLV_LIBS} ${PC_LIBS}"

m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
    [AC_ARG_WITH([pkgconfigdir],
        [AS_HELP_STRING([--with-pkgconfigdir],
            [install directory for libstrophe.pc pkg-config file])],
        [], [with_pkgconfigdir='$(libdir)/pkgconfig'])
    AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

AM_CONDITIONAL([PARSER_EXPAT], [test x$with_parser != xlibxml2])
AM_CONDITIONAL([DISABLE_TLS], [test x$enable_tls = xno])

AC_SUBST([PC_REQUIRES], [${PC_REQUIRES}])
AC_SUBST([PC_CFLAGS], [${PC_CFLAGS}])
AC_SUBST([PC_LIBS], [${PC_LIBS}])

AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_SUBST(RESOLV_LIBS)
AC_CONFIG_FILES([Makefile libstrophe.pc])
AC_OUTPUT
