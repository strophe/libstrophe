#!/bin/sh

DIR=`dirname $0`
EXPAT_PATH="$DIR/expat"
EXPAT_FILE='lib/expat.h'

echo
echo Attention: libstrophe will be built without TLS support. To enable TLS
echo you need to replace \'src/tls_dummy.c\' with \'src/tls_opnessl.c\' in
echo \'jni/Android.mk\', add path to the openssl headers and link your program
echo with libssl and libcrypto.
echo

if [ ! -d $EXPAT_PATH ]; then
    mkdir $EXPAT_PATH
fi

# TODO Accept expat tarball as argument and extract it to the right place.
#      Or download sources from sf.net.

if [ ! -d $EXPAT_PATH/lib -o ! -f "$EXPAT_PATH/$EXPAT_FILE" ]; then
    cat <<EOT
    Error: expat sources not found.

    Extract expat sources to $EXPAT_PATH. Make sure $EXPAT_PATH/$EXPAT_FILE and
    other source files exist.
EOT
    exit 1
fi

ndk-build -C "$DIR" clean || exit 1
ndk-build -C "$DIR"       || exit 1

echo
echo "basic example:"
ls -l "$DIR"/libs/*/basic
echo
echo "libstrophe.a:"
ls -l "$DIR"/obj/local/*/libstrophe.a
