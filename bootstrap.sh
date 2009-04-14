#!/bin/bash

aclocal -I /usr/local/share/aclocal
automake --add-missing --foreign --copy
autoconf