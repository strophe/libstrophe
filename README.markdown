libstrophe [![Build Status](https://travis-ci.org/strophe/libstrophe.png?branch=master)](https://travis-ci.org/strophe/libstrophe)
==========

libstrophe is a lightweight XMPP client library written in C. It has
minimal dependencies and is configurable for various environments. It
runs well on Linux, Unix and Windows based platforms.

Its goals are:

- usable quickly
- well documented
- reliable

Build Instructions
------------------

If you are building from a source control checkout, run:

    ./bootstrap.sh

to generate the `configure` script.

From the top-level directory, run the following commands:

    ./configure
    make

The public API is defined in `strophe.h` which is in the
top-level directory.

The `examples` directory contains some examples of how to
use the library; these may be helpful in addition to the
API documentation

To install on your system, as root (or using sudo):

    make install

Note, the default install path is `/usr/local/`, to specify
another path use the `--prefix` option during configure, e.g.:

    ./configure --prefix=/usr

### Android

Run script `build-android.sh` and follow the instructions. You will
need expat sources and android-ndk.

Requirements
------------

libstrophe requires:

- expat or libxml2 - expat is the default; use --with-libxml2 to
  switch
- openssl on UNIX systems

To build libstrophe using autotools you will need autoconf, automake,
libtool and pkg-config.

Installation
------------

libstrophe package has been added to popular Linux distributions,
BSD systems and OSX package managers.

Documentation
-------------

API documentation is inline with the code and conforms to Doxygen
standards. You can generate an HTML version of the API documentation
by running:

    doxygen

Then open `docs/html/index.html`.
