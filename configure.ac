m4_define([v_maj], [0])
m4_define([v_min], [12])
m4_define([v_patch], [3])
m4_define([project_version], [v_maj.v_min.v_patch])

m4_define([lt_cur], m4_eval(v_maj + v_min))
m4_define([lt_rev], v_patch)
m4_define([lt_age], v_min)

AC_INIT([libstrophe], [project_version], [jack@metajack.im])
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
    [*haiku*],     [PLATFORM="haiku"],
    [*mingw*],     [PLATFORM="win32"
                    MINGW_LIBS="-lws2_32"],
                   [PLATFORM="nix"])

WARNING_FLAGS="-Wall"

AS_CASE([$PLATFORM],
    [haiku],   [],
               [WARNING_FLAGS="$WARNING_FLAGS -Wextra"])

AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--disable-examples], [turn off examples])],
    [case "${enableval}" in yes) examples=true ;; no)  examples=false ;; *) AC_MSG_ERROR([bad value ${enableval} for --disable-examples]) ;; esac],[examples=true])
AM_CONDITIONAL([EXAMPLES], [test x$examples = xtrue])
AC_ARG_WITH([libxml2],
    [AS_HELP_STRING([--with-libxml2], [use libxml2 for XML parsing, expat is the default])])
AC_ARG_WITH([gnutls],
    [AS_HELP_STRING([--with-gnutls], [use GnuTLS for TLS support, OpenSSL is the default])])
AC_ARG_WITH([schannel],
    [AS_HELP_STRING([--with-schannel], [use Windows Schannel for TLS support, OpenSSL is the default])])
AC_ARG_ENABLE([tls],
    [AS_HELP_STRING([--disable-tls], [disable TLS support])])
AC_ARG_ENABLE([cares],
    [AS_HELP_STRING([--enable-cares], [use c-ares for DNS resolution])])
AC_ARG_ENABLE([getrandom],
    [AS_HELP_STRING([--disable-getrandom], [disable usage of the getrandom() system call])])

AC_ARG_ENABLE([fuzzing],
    [AS_HELP_STRING([--enable-fuzzing], [turn on fuzzing test])],
    [case "${enableval}" in yes) fuzzing=true ;; no)  fuzzing=false ;; *) AC_MSG_ERROR([bad value ${enableval} for --enable-fuzzing]) ;; esac],[fuzzing=false])
AM_CONDITIONAL([FUZZ], [test x$fuzzing = xtrue])

if test "x$enable_fuzzing" = "xyes" ; then
    if test "x$CC" != "xclang" ; then
        AC_MSG_ERROR(["You need to set CC=clang to use --enable-fuzzing, used $CC"])
    fi
fi

AC_ARG_ENABLE([coverage],
    [AS_HELP_STRING([--enable-coverage], [turn on coverage for tests])],
    [case "${enableval}" in yes) coverage=true ;; no)  coverage=false ;; *) AC_MSG_ERROR([bad value ${enableval} for --enable-coverage]) ;; esac],[coverage=false])
AM_CONDITIONAL([COVERAGE], [test x$coverage = xtrue])

if test "$enable_coverage" = "yes"; then
    COVERAGE_CFLAGS="--coverage -g"
    COVERAGE_LDFLAGS="--coverage -lgcov"
    COVERAGE_PRE="-Wl,--whole-archive"
    COVERAGE_POST="-Wl,--no-whole-archive"
else
    COVERAGE_CFLAGS=""
    COVERAGE_LDFLAGS=""
    COVERAGE_PRE=""
    COVERAGE_POST=""
fi

m4_include([m4/ax_valgrind_check.m4])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

AC_SEARCH_LIBS([clock_gettime], [rt], AC_DEFINE(HAVE_CLOCK_GETTIME,1))
AC_SEARCH_LIBS([socket], [network socket])
AC_CHECK_FUNCS([snprintf vsnprintf], [], [have_snprintf=no])

dnl Checking for va_copy availability
AC_MSG_CHECKING([for va_copy])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdarg.h>
va_list ap1,ap2;]], [[va_copy(ap1,ap2);]])],
have_va_copy=yes,
have_va_copy=no)
AC_MSG_RESULT($have_va_copy)
if test x"$have_va_copy" = x"yes"; then
    AC_DEFINE(HAVE_VA_COPY,1,[Whether va_copy() is available])
else
    AC_MSG_CHECKING([for __va_copy])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdarg.h>
    va_list ap1,ap2;]], [[__va_copy(ap1,ap2);]])],
    have___va_copy=yes,
    have___va_copy=no)
    AC_MSG_RESULT($have___va_copy)
    if test x"$have___va_copy" = x"yes"; then
        AC_DEFINE(HAVE___VA_COPY,1,[Whether __va_copy() is available])
    fi
fi

if test x"$have_va_copy$have___va_copy" = x"nono"; then
    dnl Checking whether va_list is an array type
    AC_MSG_CHECKING([whether va_list is an array type])
    AC_TRY_COMPILE2([
    #include <stdarg.h>
    void a(va_list * ap) {}],[
    va_list ap1, ap2; a(&ap1); ap2 = (va_list) ap1],[
      AC_MSG_RESULT(no)],[
      AC_MSG_RESULT(yes)
      AC_DEFINE([VA_LIST_IS_ARRAY], [1],[Define if va_list is an array type])])
fi

if test "x$enable_tls" != xno -a "x$with_gnutls" = xyes; then
    PKG_CHECK_MODULES([gnutls], [gnutls],
        [PC_REQUIRES="gnutls ${PC_REQUIRES}"],
        [AC_CHECK_HEADER([gnutls/gnutls.h],
            [
                gnutls_LIBS="-lgnutls"
                PC_LIBS="${gnutls_LIBS} ${PC_LIBS}"
            ],
            [AC_MSG_ERROR([gnutls not found; gnutls required])]
        )])
elif test "x$enable_tls" != xno -a "x$with_schannel" = xyes; then
    if test "x$PLATFORM" != xwin32; then
        AC_MSG_ERROR([schannel is only supported on Windows])
    fi
elif test "x$enable_tls" != xno; then
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

AC_CHECK_FUNCS([getrandom], [], [enable_getrandom=no])
if test "$enable_getrandom" = "no"; then
    AC_DEFINE(DONT_USE_GETRANDOM)
    AC_MSG_NOTICE([libstrophe will not use the getrandom() system call])
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
                    libxml2_LIBS="-lxml2 -lm"
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

if test "x$enable_cares" = xyes; then
    PKG_CHECK_MODULES([libcares], [libcares >= 1.7.0],
        [
            PC_REQUIRES="libcares ${PC_REQUIRES}"
            RESOLV_CFLAGS=$libcares_CFLAGS
            RESOLV_LIBS=$libcares_LIBS
            AC_DEFINE([HAVE_CARES])
        ],
        [AC_MSG_ERROR([libcares not found])])
        # TODO: if pkg-config doesn't find, check the library manually
else

AS_CASE([$PLATFORM],
    [bsd],     [RESOLV_LIBS=""],
    [qnx],     [RESOLV_LIBS="-lsocket"],
    [solaris], [RESOLV_LIBS="-lresolv -lsocket -lnsl"],
    [android], [RESOLV_LIBS=""],
    [haiku],   [RESOLV_LIBS="-lnetwork"],
    [win32],   [RESOLV_LIBS=""],
               [RESOLV_LIBS="-lresolv"])

if test "x$PLATFORM" != xwin32; then
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
fi

fi

m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
    [AC_ARG_WITH([pkgconfigdir],
        [AS_HELP_STRING([--with-pkgconfigdir],
            [install directory for libstrophe.pc pkg-config file])],
        [], [with_pkgconfigdir='$(libdir)/pkgconfig'])
    AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

AM_CONDITIONAL([PARSER_EXPAT], [test x$with_parser != xlibxml2])
AM_CONDITIONAL([DISABLE_TLS], [test x$enable_tls = xno])
AM_CONDITIONAL([NEED_SNPRINTF], [test x$have_snprintf = xno])
AM_CONDITIONAL([TLS_WITH_GNUTLS], [test x$with_gnutls = xyes])
AM_CONDITIONAL([TLS_WITH_SCHANNEL], [test x$with_schannel = xyes])

# define while compiling
AC_DEFINE_UNQUOTED(LIBXMPP_VERSION_MAJOR, [v_maj], [Major version])
AC_DEFINE_UNQUOTED(LIBXMPP_VERSION_MINOR, [v_min], [Minor version])

VMAJ=v_maj
VMIN=v_min
AC_SUBST(VMAJ)
AC_SUBST(VMIN)
# define in package-config file
PC_CFLAGS="${PC_CFLAGS} -DLIBXMPP_VERSION_MAJOR=${VMAJ} -DLIBXMPP_VERSION_MINOR=${VMIN}"

# set the SO version of the installed library
VERSION_INFO="lt_cur:lt_rev:lt_age"
AC_SUBST([VERSION_INFO])

AC_SUBST([PC_REQUIRES], [${PC_REQUIRES}])
AC_SUBST([PC_CFLAGS], [${PC_CFLAGS}])
AC_SUBST([PC_LIBS], [${PC_LIBS}])

AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)
AC_SUBST(COVERAGE_PRE)
AC_SUBST(COVERAGE_POST)
AC_SUBST(MINGW_LIBS)
AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_SUBST(RESOLV_CFLAGS)
AC_SUBST(RESOLV_LIBS)
AC_SUBST(WARNING_FLAGS)
AC_CONFIG_FILES([Makefile libstrophe.pc])
AC_OUTPUT
