#!/bin/sh

# Some versions of aclocal fail if m4/ doesn't exist
mkdir -p m4
autoreconf -i
