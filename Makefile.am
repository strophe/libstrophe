AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -g -Wall

PARSER_CFLAGS=@PARSER_CFLAGS@
PARSER_LIBS=@PARSER_LIBS@

SSL_CFLAGS = @openssl_CFLAGS@
SSL_LIBS = @openssl_LIBS@

RESOLV_LIBS = @RESOLV_LIBS@

STROPHE_FLAGS = -I$(top_srcdir)
STROPHE_LIBS = libstrophe.la

## Main build targets
lib_LTLIBRARIES = libstrophe.la

libstrophe_la_CFLAGS = $(SSL_CFLAGS) $(STROPHE_FLAGS) $(PARSER_CFLAGS)
libstrophe_la_LDFLAGS = $(SSL_LIBS) $(PARSER_LIBS) $(RESOLV_LIBS) -no-undefined
# Export only public API
libstrophe_la_LDFLAGS += -export-symbols-regex '^xmpp_'
libstrophe_la_SOURCES = src/auth.c src/conn.c src/crypto.c src/ctx.c \
	src/event.c src/handler.c src/hash.c src/jid.c src/md5.c \
	src/resolver.c src/sasl.c src/scram.c src/sha1.c \
	src/snprintf.c src/sock.c src/stanza.c src/util.c \
	src/rand.c src/uuid.c \
	src/common.h src/hash.h src/md5.h src/ostypes.h src/parser.h \
	src/resolver.h src/sasl.h src/scram.h src/sha1.h src/snprintf.h \
	src/sock.h src/tls.h src/util.h src/rand.h

if DISABLE_TLS
libstrophe_la_SOURCES += src/tls_dummy.c
else
libstrophe_la_SOURCES += src/tls_openssl.c
endif

if PARSER_EXPAT
libstrophe_la_SOURCES += src/parser_expat.c
else
libstrophe_la_SOURCES += src/parser_libxml2.c
endif

include_HEADERS = strophe.h
noinst_HEADERS = strophepp.h

pkgconfig_DATA = libstrophe.pc

EXTRA_DIST = docs rpm Doxyfile LICENSE.txt GPL-LICENSE.txt MIT-LICENSE.txt \
	src/tls_dummy.c src/tls_gnutls.c src/tls_schannel.c \
	examples/README.md

## Examples
noinst_PROGRAMS = examples/active examples/roster examples/basic examples/bot \
	examples/component examples/uuid
examples_active_SOURCES = examples/active.c
examples_active_CFLAGS = $(STROPHE_FLAGS)
examples_active_LDADD = $(STROPHE_LIBS)
examples_roster_SOURCES = examples/roster.c
examples_roster_CFLAGS = $(STROPHE_FLAGS)
examples_roster_LDADD = $(STROPHE_LIBS)
examples_basic_SOURCES = examples/basic.c
examples_basic_CFLAGS = $(STROPHE_FLAGS)
examples_basic_LDADD = $(STROPHE_LIBS)
examples_bot_SOURCES = examples/bot.c
examples_bot_CFLAGS = $(STROPHE_FLAGS)
examples_bot_LDADD = $(STROPHE_LIBS)
examples_component_SOURCES = examples/component.c
examples_component_CFLAGS = $(STROPHE_FLAGS)
examples_component_LDADD = $(STROPHE_LIBS)
examples_uuid_SOURCES = examples/uuid.c
examples_uuid_CFLAGS = $(STROPHE_FLAGS)
examples_uuid_LDADD = $(STROPHE_LIBS)


## Tests
TESTS = tests/check_parser tests/test_sha1 tests/test_md5 tests/test_rand \
	tests/test_scram tests/test_ctx tests/test_base64 tests/test_jid \
	tests/test_snprintf tests/test_string tests/test_resolver
check_PROGRAMS = $(TESTS)

tests_check_parser_SOURCES = tests/check_parser.c tests/test.h
tests_check_parser_CFLAGS = $(PARSER_CFLAGS) $(STROPHE_FLAGS) \
	-I$(top_srcdir)/src
tests_check_parser_LDADD = $(STROPHE_LIBS)
tests_check_parser_LDFLAGS = -static

tests_test_ctx_SOURCES = tests/test_ctx.c
tests_test_ctx_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_ctx_LDADD = $(STROPHE_LIBS)
tests_test_ctx_LDFLAGS = -static

tests_test_base64_SOURCES = tests/test_base64.c tests/test.c tests/test.h
tests_test_base64_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_base64_LDADD = $(STROPHE_LIBS)
tests_test_base64_LDFLAGS = -static

tests_test_jid_SOURCES = tests/test_jid.c
tests_test_jid_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_jid_LDADD = $(STROPHE_LIBS)
tests_test_jid_LDFLAGS = -static

tests_test_resolver_SOURCES = tests/test_resolver.c tests/test.h
tests_test_resolver_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_resolver_LDADD = $(STROPHE_LIBS)
tests_test_resolver_LDFLAGS = -static

tests_test_rand_SOURCES = tests/test_rand.c tests/test.c src/sha1.c
tests_test_rand_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src

tests_test_scram_SOURCES = tests/test_scram.c tests/test.c src/sha1.c
tests_test_scram_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src

tests_test_sha1_SOURCES = tests/test_sha1.c src/sha1.c
tests_test_sha1_CFLAGS = -I$(top_srcdir)/src

tests_test_md5_SOURCES = tests/test_md5.c tests/test.c src/md5.c
tests_test_md5_CFLAGS = -I$(top_srcdir)/src

tests_test_snprintf_SOURCES = tests/test_snprintf.c
tests_test_snprintf_CFLAGS = -I$(top_srcdir)/src

tests_test_string_SOURCES = tests/test_string.c tests/test.h
tests_test_string_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_string_LDADD = $(STROPHE_LIBS)
tests_test_string_LDFLAGS = -static
