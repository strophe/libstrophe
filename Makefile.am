AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

PARSER_CFLAGS=@PARSER_CFLAGS@
PARSER_LIBS=@PARSER_LIBS@

if TLS_WITH_GNUTLS
SSL_CFLAGS = @gnutls_CFLAGS@
SSL_LIBS = @gnutls_LIBS@
else
SSL_CFLAGS = @openssl_CFLAGS@
SSL_LIBS = @openssl_LIBS@
endif

RESOLV_CFLAGS = @RESOLV_CFLAGS@
RESOLV_LIBS = @RESOLV_LIBS@

WARNING_FLAGS = @WARNING_FLAGS@
STROPHE_FLAGS = -I$(top_srcdir) $(WARNING_FLAGS)
STROPHE_LIBS = libstrophe.la

## Main build targets
lib_LTLIBRARIES = libstrophe.la

libstrophe_la_CFLAGS = $(SSL_CFLAGS) $(STROPHE_FLAGS) $(PARSER_CFLAGS) $(RESOLV_CFLAGS)
libstrophe_la_LDFLAGS = $(SSL_LIBS) $(PARSER_LIBS) $(RESOLV_LIBS) -no-undefined
# Export only public API
libstrophe_la_LDFLAGS += -export-symbols-regex '^xmpp_'

libstrophe_la_SOURCES = \
	src/auth.c \
	src/conn.c \
	src/crypto.c \
	src/ctx.c \
	src/event.c \
	src/handler.c \
	src/hash.c \
	src/jid.c \
	src/md5.c \
	src/rand.c \
	src/resolver.c \
	src/sasl.c \
	src/scram.c \
	src/sha1.c \
	src/sha256.c \
	src/sha512.c \
	src/snprintf.c \
	src/sock.c \
	src/stanza.c \
	src/util.c \
	src/uuid.c
libstrophe_la_SOURCES += \
	src/common.h \
	src/hash.h \
	src/md5.h \
	src/ostypes.h \
	src/parser.h \
	src/rand.h \
	src/resolver.h \
	src/sasl.h \
	src/scram.h \
	src/sha.h \
	src/sha1.h \
	src/sha256.h \
	src/sha512.h \
	src/snprintf.h \
	src/sock.h \
	src/tls.h \
	src/util.h

if DISABLE_TLS
libstrophe_la_SOURCES += src/tls_dummy.c
else
if TLS_WITH_GNUTLS
libstrophe_la_SOURCES += src/tls_gnutls.c
else
libstrophe_la_SOURCES += src/tls_openssl.c
endif
endif

if PARSER_EXPAT
libstrophe_la_SOURCES += src/parser_expat.c
else
libstrophe_la_SOURCES += src/parser_libxml2.c
endif

include_HEADERS = strophe.h

pkgconfig_DATA = libstrophe.pc

EXTRA_DIST = \
	_clang-format \
	Doxyfile \
	GPL-LICENSE.txt \
	LICENSE.txt \
	MIT-LICENSE.txt \
	bootstrap.sh \
	build-android.sh \
	examples/README.md \
	jni/Android.mk \
	jni/Application.mk \
	src/tls_schannel.c \
	tests/res_query_dump.c

if TLS_WITH_GNUTLS
EXTRA_DIST += src/tls_openssl.c
else
EXTRA_DIST += src/tls_gnutls.c
endif

## Examples
noinst_PROGRAMS = \
	examples/active \
	examples/basic \
	examples/bot \
	examples/component \
	examples/roster \
	examples/uuid \
	examples/vcard \
	examples/register

examples_active_SOURCES = examples/active.c
examples_active_CFLAGS = $(STROPHE_FLAGS)
examples_active_LDADD = $(STROPHE_LIBS)
examples_basic_SOURCES = examples/basic.c
examples_basic_CFLAGS = $(STROPHE_FLAGS)
examples_basic_LDADD = $(STROPHE_LIBS)
examples_bot_SOURCES = examples/bot.c
examples_bot_CFLAGS = $(STROPHE_FLAGS)
examples_bot_LDADD = $(STROPHE_LIBS)
examples_component_SOURCES = examples/component.c
examples_component_CFLAGS = $(STROPHE_FLAGS)
examples_component_LDADD = $(STROPHE_LIBS)
examples_roster_SOURCES = examples/roster.c
examples_roster_CFLAGS = $(STROPHE_FLAGS)
examples_roster_LDADD = $(STROPHE_LIBS)
examples_uuid_SOURCES = examples/uuid.c
examples_uuid_CFLAGS = $(STROPHE_FLAGS)
examples_uuid_LDADD = $(STROPHE_LIBS)
examples_vcard_SOURCES = examples/vcard.c
examples_vcard_CFLAGS = $(STROPHE_FLAGS)
examples_vcard_LDADD = $(STROPHE_LIBS)
examples_register_SOURCES = examples/register.c
examples_register_CFLAGS = $(STROPHE_FLAGS)
examples_register_LDADD = $(STROPHE_LIBS)


## Tests
TESTS = \
	tests/check_parser \
	tests/test_sha1 \
	tests/test_sha256 \
	tests/test_sha512 \
	tests/test_md5 \
	tests/test_rand \
	tests/test_scram \
	tests/test_ctx \
	tests/test_base64 \
	tests/test_hash \
	tests/test_jid \
	tests/test_snprintf \
	tests/test_string \
	tests/test_stanza \
	tests/test_resolver

if !DISABLE_TLS
TESTS += tests/test_xmppaddr
endif

check_PROGRAMS = $(TESTS)

if FUZZ
check_PROGRAMS += tests/test_fuzz

tests_test_fuzz_SOURCES = tests/test_fuzz.c
tests_test_fuzz_CFLAGS = -fsanitize=fuzzer,address  $(PARSER_CFLAGS) $(STROPHE_FLAGS) \
	-I$(top_srcdir)/src
tests_test_fuzz_LDADD = $(STROPHE_LIBS)
tests_test_fuzz_LDFLAGS = -static
endif

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

tests_test_hash_SOURCES = tests/test_hash.c
tests_test_hash_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_hash_LDADD = $(STROPHE_LIBS)
tests_test_hash_LDFLAGS = -static

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

tests_test_scram_SOURCES = tests/test_scram.c tests/test.c src/sha1.c \
	src/sha256.c src/sha512.c
tests_test_scram_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src

tests_test_sha1_SOURCES = tests/test_sha1.c src/sha1.c
tests_test_sha1_CFLAGS = -I$(top_srcdir)/src

tests_test_sha256_SOURCES = tests/test_sha256.c tests/test.c src/sha256.c
tests_test_sha256_CFLAGS = -I$(top_srcdir)/src

tests_test_sha512_SOURCES = tests/test_sha512.c tests/test.c src/sha512.c
tests_test_sha512_CFLAGS = -I$(top_srcdir)/src

tests_test_md5_SOURCES = tests/test_md5.c tests/test.c src/md5.c
tests_test_md5_CFLAGS = -I$(top_srcdir)/src

tests_test_snprintf_SOURCES = tests/test_snprintf.c
tests_test_snprintf_CFLAGS = -I$(top_srcdir)/src

tests_test_string_SOURCES = tests/test_string.c tests/test.h
tests_test_string_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_string_LDADD = $(STROPHE_LIBS)
tests_test_string_LDFLAGS = -static

tests_test_stanza_SOURCES = tests/test_stanza.c
tests_test_stanza_CFLAGS = $(STROPHE_FLAGS)
tests_test_stanza_LDADD = $(STROPHE_LIBS)
tests_test_stanza_LDFLAGS = -static

tests_test_xmppaddr_SOURCES = tests/test_xmppaddr.c
tests_test_xmppaddr_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_xmppaddr_LDADD = $(STROPHE_LIBS)
tests_test_xmppaddr_LDFLAGS = -static

format:
	@echo "   * run clang-format on all sources"
	@dos2unix -q src/*.[ch] *.h tests/*.[ch] examples/*.c
	@clang-format -i src/*.[ch] *.h tests/*.[ch] examples/*.c
