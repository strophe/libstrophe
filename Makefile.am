AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

COVERAGE_CFLAGS=@COVERAGE_CFLAGS@
COVERAGE_LDFLAGS=@COVERAGE_LDFLAGS@
COVERAGE_PRE=@COVERAGE_PRE@
COVERAGE_POST=@COVERAGE_POST@

PARSER_CFLAGS=@PARSER_CFLAGS@
PARSER_LIBS=@PARSER_LIBS@

if TLS_WITH_GNUTLS
SSL_CFLAGS = @gnutls_CFLAGS@
SSL_LIBS = @gnutls_LIBS@
else
if !TLS_WITH_SCHANNEL
SSL_CFLAGS = @openssl_CFLAGS@
SSL_LIBS = @openssl_LIBS@
endif
endif

MINGW_LIBS = @MINGW_LIBS@

RESOLV_CFLAGS = @RESOLV_CFLAGS@
RESOLV_LIBS = @RESOLV_LIBS@

WARNING_FLAGS = @WARNING_FLAGS@
STROPHE_FLAGS = -I$(top_srcdir) $(WARNING_FLAGS)
STROPHE_LIBS = $(COVERAGE_PRE) libstrophe.la $(COVERAGE_POST) $(COVERAGE_LDFLAGS)

## Main build targets
lib_LTLIBRARIES = libstrophe.la

libstrophe_la_CFLAGS = $(SSL_CFLAGS) $(STROPHE_FLAGS) $(PARSER_CFLAGS) $(RESOLV_CFLAGS) $(COVERAGE_CFLAGS)
libstrophe_la_LDFLAGS = $(SSL_LIBS) $(PARSER_LIBS) $(RESOLV_LIBS) $(MINGW_LIBS) -no-undefined
# Export only public API
libstrophe_la_LDFLAGS += -export-symbols-regex '^xmpp_' -version-info @VERSION_INFO@

libstrophe_la_SOURCES = \
	src/auth.c \
	src/conn.c \
	src/crypto.c \
	src/ctx.c \
	src/deprecated.c \
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
	src/sock.c \
	src/stanza.c \
	src/tls.c \
	src/util.c \
	src/uuid.c
libstrophe_la_SOURCES += \
	src/common.h \
	src/hash.h \
	src/md5.h \
	src/ostypes.h \
	src/parser.h \
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

if NEED_SNPRINTF
libstrophe_la_SOURCES += src/snprintf.c
endif

if DISABLE_TLS
libstrophe_la_SOURCES += src/tls_dummy.c
else
if TLS_WITH_GNUTLS
libstrophe_la_SOURCES += src/tls_gnutls.c
else
if TLS_WITH_SCHANNEL
libstrophe_la_SOURCES += src/tls_schannel.c
else
libstrophe_la_SOURCES += src/tls_openssl.c
endif
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
	testbuild.sh \
	examples/README.md \
	jni/Android.mk \
	jni/Application.mk \
	m4/ax_valgrind_check.m4 \
	tests/cert.pem \
	tests/cert.pfx \
	tests/cert.emptypass.pfx \
	tests/cert.nopass.pfx \
	tests/key.pem \
	tests/key_encrypted.pem \
	tests/res_query_dump.c

if EXAMPLES
## Examples
noinst_PROGRAMS = \
	examples/active \
	examples/basic \
	examples/bot \
	examples/complex \
	examples/component \
	examples/perf \
	examples/register \
	examples/roster \
	examples/uuid \
	examples/vcard

examples_active_SOURCES = examples/active.c
examples_active_CFLAGS = $(STROPHE_FLAGS)
examples_active_LDADD = $(STROPHE_LIBS)
examples_basic_SOURCES = examples/basic.c
examples_basic_CFLAGS = $(STROPHE_FLAGS)
examples_basic_LDADD = $(STROPHE_LIBS)
examples_bot_SOURCES = examples/bot.c
examples_bot_CFLAGS = $(STROPHE_FLAGS)
examples_bot_LDADD = $(STROPHE_LIBS)
examples_complex_SOURCES = examples/complex.c
examples_complex_CFLAGS = $(STROPHE_FLAGS)
examples_complex_LDADD = $(STROPHE_LIBS)
examples_component_SOURCES = examples/component.c
examples_component_CFLAGS = $(STROPHE_FLAGS)
examples_component_LDADD = $(STROPHE_LIBS)
examples_perf_SOURCES = examples/perf.c
examples_perf_CFLAGS = $(STROPHE_FLAGS)
examples_perf_LDADD = $(STROPHE_LIBS)
examples_register_SOURCES = examples/register.c
examples_register_CFLAGS = $(STROPHE_FLAGS)
examples_register_LDADD = $(STROPHE_LIBS)
examples_roster_SOURCES = examples/roster.c
examples_roster_CFLAGS = $(STROPHE_FLAGS)
examples_roster_LDADD = $(STROPHE_LIBS)
examples_uuid_SOURCES = examples/uuid.c
examples_uuid_CFLAGS = $(STROPHE_FLAGS)
examples_uuid_LDADD = $(STROPHE_LIBS)
examples_vcard_SOURCES = examples/vcard.c
examples_vcard_CFLAGS = $(STROPHE_FLAGS)
examples_vcard_LDADD = $(STROPHE_LIBS)
endif


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
	tests/test_send_queue \
	tests/test_snprintf \
	tests/test_string \
	tests/test_stanza \
	tests/test_resolver

if !DISABLE_TLS
TESTS += tests/test_xmppaddr
endif

check_PROGRAMS = $(TESTS)

if FUZZ
check_PROGRAMS += tests/test_fuzz_parser tests/test_fuzz_resolver

tests_test_fuzz_parser_SOURCES = tests/test_fuzz_parser.c
tests_test_fuzz_parser_CFLAGS = -fsanitize=fuzzer,address  $(PARSER_CFLAGS) $(STROPHE_FLAGS) \
	-I$(top_srcdir)/src
tests_test_fuzz_parser_LDADD = $(STROPHE_LIBS)
tests_test_fuzz_parser_LDFLAGS = -static

tests_test_fuzz_resolver_SOURCES = tests/test_fuzz_resolver.c
tests_test_fuzz_resolver_CFLAGS = -fsanitize=fuzzer,address  $(resolver_CFLAGS) $(STROPHE_FLAGS) \
	-I$(top_srcdir)/src
tests_test_fuzz_resolver_LDADD = $(STROPHE_LIBS)
tests_test_fuzz_resolver_LDFLAGS = -static
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

tests_test_send_queue_SOURCES = tests/test_send_queue.c
tests_test_send_queue_CFLAGS = -I$(top_srcdir)/src
tests_test_send_queue_LDADD = $(STROPHE_LIBS)
tests_test_send_queue_LDFLAGS = -static

tests_test_snprintf_SOURCES = tests/test_snprintf.c
tests_test_snprintf_CFLAGS = -I$(top_srcdir)/src

tests_test_string_SOURCES = tests/test_string.c tests/test.h
tests_test_string_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_string_LDADD = $(STROPHE_LIBS)
tests_test_string_LDFLAGS = -static

tests_test_stanza_SOURCES = tests/test_stanza.c tests/test.h
tests_test_stanza_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_stanza_LDADD = $(STROPHE_LIBS)
tests_test_stanza_LDFLAGS = -static

tests_test_xmppaddr_SOURCES = tests/test_xmppaddr.c
tests_test_xmppaddr_CFLAGS = $(STROPHE_FLAGS) -I$(top_srcdir)/src
tests_test_xmppaddr_LDADD = $(STROPHE_LIBS)
tests_test_xmppaddr_LDFLAGS = -static

format:
	@echo "   * run clang-format on all sources"
	@dos2unix -k -q $(top_srcdir)/src/*.[ch] $(top_srcdir)/*.h $(top_srcdir)/tests/*.[ch] $(top_srcdir)/examples/*.c
	@clang-format -i $(top_srcdir)/src/*.[ch] $(top_srcdir)/*.h $(top_srcdir)/tests/*.[ch] $(top_srcdir)/examples/*.c

if COVERAGE
MOSTLYCLEANFILES = src/*.gcno src/*.gcda coverage.info
clean-local:
	-rm -rf coverage/

coverage: check
	@lcov --capture --no-external --directory src -q --output-file coverage.info
	@genhtml coverage.info --output-directory coverage -q
endif

release: test-release-all

dist-archives:
	$(MAKE) dist
	$(MAKE) dist-bzip2
	$(MAKE) dist-xz

test-release: dist
	@touch testbuild-$(PACKAGE_VERSION).log && ln -sf testbuild-$(PACKAGE_VERSION).log testbuild.log
	@mkdir -p test-release && cp $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.* test-release && pushd test-release && \
		tar xzf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz  && pushd $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && ./testbuild.sh && popd && rm -rf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && \
		echo "Success" && popd

test-release-all: dist-archives
	@touch testbuild-$(PACKAGE_VERSION).log && ln -sf testbuild-$(PACKAGE_VERSION).log testbuild.log
	@mkdir -p test-release && cp $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.* test-release && pushd test-release && \
		tar xJf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.xz  && pushd $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && ./testbuild.sh && popd && rm -rf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && \
		tar xjf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.bz2 && pushd $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && ./testbuild.sh && popd && rm -rf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && \
		tar xzf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz  && pushd $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && ./testbuild.sh && popd && rm -rf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION) && \
		echo "Success" && popd

docs:
	@SRCDIR=$(top_srcdir) doxygen -q $(top_srcdir)/Doxyfile

@VALGRIND_CHECK_RULES@

.PHONY: docs test-release
