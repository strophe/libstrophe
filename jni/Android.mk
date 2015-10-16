LOCAL_PATH:= $(call my-dir)

#
# examples/basic
#

include $(CLEAR_VARS)
LOCAL_MODULE := basic
LOCAL_CFLAGS :=
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/..

LOCAL_SRC_FILES := \
	../examples/basic.c

LOCAL_STATIC_LIBRARIES := libstrophe libexpat

include $(BUILD_EXECUTABLE)

#
# libstrohe (static library)
#

include $(CLEAR_VARS)
LOCAL_MODULE := libstrophe
LOCAL_CFLAGS :=
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/.. \
	$(LOCAL_PATH)/../src \
	$(LOCAL_PATH)/../expat/lib

LOCAL_SRC_FILES := \
	../src/auth.c \
	../src/conn.c \
	../src/crypto.c \
	../src/ctx.c \
	../src/event.c \
	../src/handler.c \
	../src/hash.c \
	../src/jid.c \
	../src/md5.c \
	../src/parser_expat.c \
	../src/rand.c \
	../src/resolver.c \
	../src/sasl.c \
	../src/scram.c \
	../src/sha1.c \
	../src/snprintf.c \
	../src/sock.c \
	../src/stanza.c \
	../src/tls_dummy.c \
	../src/util.c \
	../src/uuid.c

LOCAL_STATIC_LIBRARIES := libstrophe

include $(BUILD_STATIC_LIBRARY)

#
# expat
#

include $(CLEAR_VARS)
LOCAL_MODULE := libexpat
LOCAL_CFLAGS := -DHAVE_MEMMOVE
#LOCAL_C_INCLUDES := \
#	$(LOCAL_PATH)/expat

LOCAL_SRC_FILES := \
	../expat/lib/xmlparse.c \
	../expat/lib/xmlrole.c \
	../expat/lib/xmltok.c \
	../expat/lib/xmltok_impl.c \
	../expat/lib/xmltok_ns.c

LOCAL_STATIC_LIBRARIES := libexpat

include $(BUILD_STATIC_LIBRARY)
