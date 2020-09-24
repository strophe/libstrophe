#!/bin/sh

if [ "x$LIBRESSL" = "xyes" ]; then
    cd "$HOME"
    git clone https://github.com/libressl-portable/portable.git libressl-git
    cd libressl-git
    if [ -n "$LIBRESSL_COMMIT" ]; then
        git checkout "$LIBRESSL_COMMIT"
    fi
    ./autogen.sh
    ./configure --prefix="$HOME/libressl"
    make -j"$(nproc)"
    make install
fi
