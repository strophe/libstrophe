#!/bin/sh

set -e

[ "x$XSSL_COMMITISH" != "x" ]

if [ "x$LIBRESSL" = "xtrue" ]; then
    REPO_URL="https://github.com/libressl-portable/portable.git"
    AUTOGEN_CMD="./autogen.sh"
    CONFIG_CMD="./configure --prefix=$HOME/xssl"
    MAKE_TARGET="install"
else
    REPO_URL="https://github.com/openssl/openssl.git"
    AUTOGEN_CMD="true"
    CONFIG_CMD="./Configure --prefix=$HOME/xssl --libdir=lib"
    MAKE_TARGET="install_sw"
fi

cd "$HOME"
git clone --no-checkout "$REPO_URL" xssl-git
cd xssl-git
git checkout "$XSSL_COMMITISH"
$AUTOGEN_CMD
$CONFIG_CMD
make -j"$(nproc)"
make $MAKE_TARGET
