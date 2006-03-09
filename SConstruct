# -*- Mode: python -*-
# SCons build specification
# see http://www.scons.org if you do not have this tool

# Copyright (C) 2005 OGG, LCC. All rights reserved.
#  This software is provided AS-IS with no warranty, either express or
#  implied.
#
#  This software is distributed under license and may not be copied,
#  modified or distributed except as expressly authorized under the 
#  terms of the license contained in the file LICENSE.txt in this 
#  distribution.

# This source code is distributed under specific license
# terms. See LICENSE.txt for details.

# invoke with 'scons' to build the library

LIBSTROPHE_VERSION_MAJOR=0
LIBSTROPHE_VERSION_MINOR=7

from os.path import join

# TODO: should use lamda and map to work on python 1.5
def path(prefix, list): return [join(prefix, x) for x in list]

ExpatSources = Split("""
  xmlparse.c
  xmltok.c
  xmlrole.c
""")

Sources = Split("""
  ctx.c
  conn.c
  parser.c
  handler.c
  auth.c
  event.c
  stanza.c
  jid.c
  sock.c
  hash.c
  sasl.c
  sha1.c
  md5.c
  util.c
  thread.c
  snprintf.c
  oocontext.cpp
  oostanza.cpp
""")

Headers = Split("""
  strophe.h
  common.h
  sock.h
  hash.h
  sha1.h
  md5.h
  util.h
  thread.h
""")

Examples = Split("""
  basic.c
  active.c
  roster.c
""")

env = Environment()
if env['CC'] == 'gcc':
  env.Append(CCFLAGS=["-g", "-Wall"])

expatenv = env.Copy()
# feature defs
expatenv.Append(CCFLAGS=" -DXML_DTD")
expatenv.Append(CCFLAGS=" -DXML_NS")
expatenv.Append(CCFLAGS=" -DXML_CONTEXT_BYTES=1024")
# sys config defs (these should be autodetected)
expatenv.Append(CCFLAGS=" -DBYTEORDER=4321")
expatenv.Append(CCFLAGS=" -DHAVE_MEMMOVE")
expatenv.Append(CCFLAGS=" -DHAVE_UNISTD")

expat = expatenv.Library('expat', path(join('expat', 'lib'), ExpatSources))
Default(expat)

stropheenv = env.Copy()
stropheenv.Append(CCFLAGS=" -DXML_STATIC")
stropheenv.Append(CPPPATH=['.', 'src', join('expat','lib')])

strophe = stropheenv.Library('strophe', path("src", Sources))
Default(strophe)

exenv = env.Copy()
exenv.Append(CPPPATH=['.'])
exenv.Append(LIBS=["strophe", "expat"])
exenv.Append(LIBPATH=["."])
if exenv["PLATFORM"] == "win32":
  exenv.Append(LIBS=["ws2_32", "winmm"])
for e in path("examples", Examples):
  example = exenv.Program(e)
  Default(example)

# generate a MSVC project for convenience
# TODO: this doesn't seem to be implemented?
#env.MSVSProject(target = 'strophe' + env['MSVSPROJECTSUFFIX'],
#	srcs = path("src", Sources), incs = path("src", Headers),
#	variant = 'Release', buildtarget = strophe)

### unit and regression tests

import unittest
from os import popen

class RunnableTestCase(unittest.TestCase):
  def __init__(self, file):
    self.file = str(file)
    unittest.TestCase.__init__(self)
  def shortDescription(self):
    return "Running '%s'" % self.file
  def runTest(self):
    '''C tests should return '0' on exit'''
    test = popen(self.file)
    self.failIf(test.close(), "unit '%s' did not exit normally" % self.file)

def testcase_runner(target, source, env):
  suite = unittest.TestSuite()
  for test in source:
    #suite.addTest(RunnableTestCase(test[0]))
    suite.addTest(RunnableTestCase(test))
  result = unittest.TextTestRunner(verbosity=2).run(suite)
  env.Execute(Touch(str(target[0])))

testenv = env.Copy()
testenv.Append(CPPPATH=['.', 'src', join('expat','lib')])
testenv.Append(LIBS=['strophe', 'expat'])
if testenv["PLATFORM"] == "win32":
  testenv.Append(LIBS=["winmm", "ws2_32"])
testenv.Append(LIBPATH=['.'])

import SCons.Node
test_builder = Builder(action = testcase_runner,
		multi = 1)

testenv.Append(BUILDERS = {'TestCase' : test_builder})

# application source files for unit tests
tests = Split("""
  test_ctx.c
  test_sock.c
  test_hash.c
  test_base64.c
  test_sasl.c
  test_jid.c
""")

# build each test and add it to the 'test' pseudo target
for test in path("tests", tests):
  tests = testenv.TestCase('test_stamp', testenv.Program(test))
testenv.AlwaysBuild(tests)
testenv.Alias('test', tests)
