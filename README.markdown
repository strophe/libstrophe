# libstrophe

libstrophe is a lightweight XMPP client library written in C. It has
minimal dependencies and is configurable for various environments. It
runs well on both Linux, Unix, and Windows based platforms.

Its goals are:

- usable quickly
- well documented
- reliable

## Build Instructions

If you are building from a source control checkout, run:

    ./bootstrap.sh

to generate the `configure` script.

From the top-level directory, run the following commands:

    ./configure
    make

This will create a static library, also in the top-level
directory, which can be linked into other programs. The 
public API is defined in `strophe.h` which is also in the
top-level directory.

The `examples` directory contains some examples of how to
use the library; these may be helpful in addition to the
API documentation

To install on your system, as root (or using sudo):

    make install

Note, the default install path is `/usr/local/`, to specify
another path use the `--prefix` option during configure, e.g.:

    ./configure --prefix=/usr

## Requirements

libstrophe requires:

- expat or libxml2 - expat is the default; use --with-libxml2 to
  switch
- libresolv on UNIX systems - make sure you include -lresolv
  if you are compiling by hand. 
- libtool

In addition, if you wish to run the unit tests, you will need the
check package.

### OS X (with Homebrew package manager)

You can install the requirements with:

    brew install expat
    brew install check

## Documentation

API documentation is inline with the code and conforms to Doxygen
standards. You can generate an HTML version of the API documentation
by running:

    doxygen

Then open `docs/html/index.html`.
