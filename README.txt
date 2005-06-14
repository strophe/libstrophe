This is libstrophe, our experimental XMPP C client library.

Our goals are:

    (a) usable quickly
    (b) well documented
    (c) reliable
    (d) not suck

And to implement the complete XMPP spec, but not the historical Jabber 
bits.

== Build Instructions ==

We use the 'scons' tool to build the library, unit tests, 
documentation and examples. You'll need to obtain a copy
from http://www.scons.org/ or from your system distributor.

Once scons is installed, invoke 'scons' in the top-level
directory to build the library. This will create a static
library (also in the top-level) directory which can be
linked into other programs. The public api is defined
in <xmpp.h> which is also in the top-level directory.

Invoke 'scons test' in the top-level directory to execute
the unit and self tests.

The examples/ directory contains some examples of how to
use the library; these may be helpful in addition to the
API documentation in doc/.

