#!/bin/sh

ACFLAGS=""
if [ -d /usr/local/share/aclocal ]; then
    ACFLAGS="-I /usr/local/share/aclocal"
fi

aclocal ${ACFLAGS}
automake --add-missing --foreign --copy
autoconf
