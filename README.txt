This is strophe, our XMPP client library.

Our goals are:

    * usable quickly
    * well documented
    * reliable

== Build Instructions ==

We use the 'scons' tool to build the library, unit tests, 
documentation and examples. You'll need to obtain a copy
from http://www.scons.org/ or from your system distributor.

Once scons is installed, invoke 'scons' in the top-level
directory to build the library. This will create a static
library (also in the top-level) directory which can be
linked into other programs. The public api is defined
in <strophe.h> which is also in the top-level directory.

Invoke 'scons test' in the top-level directory to execute
the unit and self tests.

The examples/ directory contains some examples of how to
use the library; these may be helpful in addition to the
API documentation in doc/.


== Requirements ==

Libstrophe requires libresolv on UNIX systems. Make sure you include -lresolv
if you are compiling by hand.

It also uses expat for XML processing, but a current copy is included in the
expat/ directory of the SVN checkout


