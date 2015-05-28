#!python

# Configure -- python version
#
# this script builds Visual Studio files

import sys
import os
import os.path
import re
import subprocess

# files to configure

filelist = ["config.h",
            "softhsm2.sln",
            "convarch\\convarch.vcxproj.filters",
            "convarch\\convarch.vcxproj",
            "cryptotest\\cryptotest.vcxproj",
            "datamgrtest\\datamgrtest.vcxproj",
            "dump\\dump.vcxproj",
            "handlemgrtest\\handlemgrtest.vcxproj",
            "keyconv\\keyconv.vcxproj.filters",
            "keyconv\\keyconv.vcxproj",
            "objstoretest\\objstoretest.vcxproj",
            "p11test\\p11test.vcxproj",
            "sessionmgrtest\\sessionmgrtest.vcxproj",
            "slotmgrtest\\slotmgrtest.vcxproj",
            "softhsm2\\softhsm2.vcxproj",
            "util\\util.vcxproj.filters",
            "util\\util.vcxproj"]

# test files
testlist = ["botan",
            "ecc",
            "gnump",
            "gost",
            "ossl",
            "osslv",
            "rfc3394",
            "rfc5649"]

# variables to expand

varvals = {}

varnames = ["CUINCPATH",
            "CULIBPATH",
            "DEBUGDLLPATH",
            "DEBUGINCPATH",
            "DEBUGLIBPATH",
            "DLLPATH",
            "EXTRALIBS",
            "INCLUDEPATH",
            "LIBNAME",
            "LIBPATH",
            "PLATFORM",
            "PLATFORMDIR"]

# conditions to stack

condvals = {}

condnames = ["BOTAN",
             "ECC",
             "GOST",
             "NONPAGE",
             "OPENSSL",
             "RFC3394",
             "RFC5649",
             "TESTS"]

# enable-xxx/disable-xxx arguments

enablelist = ["64bit",
              "debug",
              "ecc",
              "gost",
              "keep",
              "non-paged-memory",
              "verbose"]

# with-xxx/without-xxx arguments

withlist = ["botan",
            "cppunit",
            "crypto-backend",
            "debug-botan",
            "debug-openssl",
            "openssl"]

# general commands

commandlist = ["help", "clean"] # verbose, keep

# usage

usage = ["Usage: python Configure.pl help",
         "       python Configure.pl options*",
         "       python Configure.pl clean"]

# help

myhelp = ["'python Configure.pl' configures SoftHSMv2 build files.\n"] +\
usage + [\
"\nGeneral Commands:",
"  help                     print this help",
"  clean                    clean up generated files",
"  <none>                   print a summary of the configuration",
"\nOptional Features:",
"  enable-verbose           print messages [default=no]",
"  enable-keep              keep test files after config [default=no]",
"  enable-64bit             enable 64-bit compiling [default=no]",
"  enable-debug             enable build of Debug config [default=yes]",
"  enable-ecc               enable support for ECC [default=yes]",
"  enable-gost              enable support for GOST [default=yes]",
"  enable-non-paged-memory  enable non-paged memory [default=yes]",
"\nOptional Packages:",
"  with-crypto-backend      select the crypto backend [openssl|botan]",
"  with-botan=PATH          speficy prefix of path of Botan (Release)",
"  with-debug-botan=PATH    speficy prefix of path of Botan (Debug)",
"  with-openssl=PATH        speficy prefix of path of OpenSSL (Release)",
"  with-debug-openssl=PATH  speficy prefix of path of OpenSSL (Debug)",
"  with-cppunit=PATH        specify prefix of path of CppUnit"]

# variables for parsing

verbose = False
configargs = None
want_help = False
want_clean = False
want_unknown = False
unknown_value = None
enable_keep = False
enable_debug = True
enable_ecc = True
enable_gost = True
enable_non_paged = True
platform = 32
crypto_backend = "openssl"
botan_path = "..\\..\\btn"
debug_botan_path = None
openssl_path = "..\\..\\ssl"
debug_openssl_path = None
want_tests = True
cppunit_path = "..\\..\\cu"

def parseargs(args):
    """parse arguments"""
    global verbose
    global enable_keep
    global want_help
    global want_clean
    global want_unknown
    global unknown_value
    global debug_botan_path
    global debug_openssl_path
    for arg in args:
        if arg.lower() == "verbose":
            verbose = True
            continue
        if arg.lower() == "keep":
            enable_keep = True
            continue
        if arg.lower() == "help":
            want_help = True
            continue
        di = re.match(r'disable-(.*)', arg, re.I)
        if di:
            appargs(arg)
            myenable(di.group(1), False)
            continue
        en = re.match(r'enable-(.*)', arg, re.I)
        if en:
            appargs(arg)
            myenable(en.group(1), True)
            continue
        wo = re.match(r'without-(.*)', arg, re.I)
        if wo:
            appargs(arg)
            mywith(wo.group(1), False)
            continue
        wv = re.match(r'with-(.*)=(.*)', arg, re.I)
        if wv:
            appargs(arg)
            if wv.group(2).lower() == "no":
                mywith(wv.group(1), False)
                continue
            mywith(wv.group(1), True, wv.group(2))
            continue
        wi = re.match(r'with-(.*)', arg, re.I)
        if wi:
            appargs(arg)
            mywith(wi.group(1), True)
            continue
        if arg.lower() == "clean":
            want_clean = True
            continue
        want_unknown = True
        unknown_value = arg
        break

    # debug
    if enable_debug:
        if debug_botan_path is None:
            debug_botan_path = botan_path + "_d"
        if debug_openssl_path is None:
            debug_openssl_path = openssl_path + "_d"

def appargs(arg):
    """append seen arguments to configargs"""
    global configargs
    # escape backslashes, spaces and double quotes
    escaped = ""
    for x in arg:
        if (x == "\\") or (x == " ") or (x == "\""):
            escaped += "\\"
        escaped += x
    if configargs:
        configargs += " " + escaped
    else:
        configargs = escaped

def myenable(key, val):
    """parse enable/disable"""
    global platform
    global enable_debug
    global enable_ecc
    global enable_gost
    global enable_non_paged
    global enable_keep
    global verbose
    global want_unknown
    global unknown_value
    if key.lower() == "64bit":
        if val:
            platform = 64
        return
    if key.lower() == "debug":
        if not val:
            enable_debug = False
        return
    if key.lower() == "ecc":
        if not val:
            enable_ecc = False
        return
    if key.lower() == "gost":
        if not val:
            enable_gost = False
        return
    if key.lower() == "non-paged-memory":
        if not val:
            enable_non_paged = False
        return
    if key.lower() == "keep":
        if val:
            enable_keep = True
        return
    if key.lower() == "verbose":
        if val:
            verbose = True
        return
    want_unknown = True
    if not val:
        unknown_value = "disable-" + key
    else:
        unknown_value = "enable-" + key

def mywith(key, val, detail=None):
    """parse with/without"""
    global crypto_backend
    global botan_path
    global debug_botan_path
    global openssl_path
    global debug_openssl_path
    global want_tests
    global cppunit_path
    global want_unknown
    global unknown_value
    if key.lower() == "crypto-backend":
        if val and (detail.lower() == "openssl"):
            crypto_backend = "openssl"
            return
        if val and (detail.lower() == "botan"):
            crypto_backend = "botan"
            return
        want_unknown = True
        unknown_value = "with-crypto-backend=" + detail
        return
    if key.lower() == "botan":
        if not val:
            want_unknown = True
            unknown_value = "without-botan doesn't make sense"
            return
        if detail.lower() != "yes":
            botan_path = detail
        return
    if key.lower() == "debug-botan":
        if not val:
            want_unknown = True
            unknown_value = "without-debug-botan doesn't make sense"
            return
        if detail.lower() != "yes":
            debug_botan_path = detail
        return
    if key.lower() == "openssl":
        if not val:
            want_unknown = True
            unknown_value = "without-openssl doesn't make sense"
            return
        if detail.lower() != "yes":
            openssl_path = detail
        return
    if key.lower() == "debug-openssl":
        if not val:
            want_unknown = True
            unknown_value = "without-debug-openssl doesn't make sense"
            return
        if detail.lower() != "yes":
            debug_openssl_path = detail
        return
    if key.lower() == "cppunit":
        if not val:
            want_tests = False
            return
        if detail.lower() != "yes":
            cppunit_path = detail
        return
    want_unknown = True
    if not val:
        unknown_value = "without-" + key
    else:
        unknown_value = "with-" + key

def dohelp():
    """help"""
    for line in myhelp:
        print line
    sys.exit(1)

def docleantest():
    """clean test files"""
    for basename in testlist:
        filename = "test" + basename + ".c"
        if os.path.isfile(filename):
            os.unlink(filename)
        filename = "test" + basename + ".cpp"
        if os.path.isfile(filename):
            os.unlink(filename)
        filename = "test" + basename + ".obj"
        if os.path.isfile(filename):
            os.unlink(filename)
        filename = "test" + basename + ".exe"
        if os.path.isfile(filename):
            os.unlink(filename)
    if os.path.isfile("botan.dll"):
        os.unlink("botan.dll")
    if os.path.isfile("libeay32.dll"):
        os.unlink("libeay32.dll")

def doclean():
    """clean"""
    docleantest()
    for filename in filelist:
        if os.path.isfile(filename):
            os.unlink(filename)
    sys.exit(0)

def dounknown():
    """parsing error"""
    print >> sys.stderr, "can't parse " + unknown_value + ""
    sys.exit(1)

def doconfig():
    """config itself"""
    global botan_path
    global debug_botan_path
    global openssl_path
    global debug_openssl_path
    global cppunit_path

    # configure the platform
    if platform == 32:
        varvals["PLATFORM"] = "Win32"
    else:
        varvals["PLATFORM"] = "x64"
        varvals["PLATFORMDIR"] = "x64\\"

    # configure ECC and GOST
    if enable_ecc:
        condvals["ECC"] = True
    if enable_gost:
        condvals["GOST"] = True

    # configure the crypto
    if crypto_backend == "botan":
        condvals["BOTAN"] = True
        varvals["LIBNAME"] = "botan.lib"
        botan_path = os.path.abspath(botan_path)
        botan_dll = os.path.join(botan_path, "botan.dll")
        varvals["DLLPATH"] = botan_dll
        botan_inc = os.path.join(botan_path, "include")
        if not os.path.exists(os.path.join(botan_inc, "botan\\init.h")):
            print >> sys.stderr, "can't find Botan includes"
            sys.exit(1)
        varvals["INCLUDEPATH"] = botan_inc
        if not os.path.exists(os.path.join(botan_path, "botan.lib")):
            print >> sys.stderr, "can't find Botan library"
            sys.exit(1)
        varvals["LIBPATH"] = botan_path
        if enable_debug:
            debug_botan_path = os.path.abspath(debug_botan_path)
            varvals["DEBUGDLLPATH"] = \
                os.path.join(debug_botan_path, "botan.dll")
            debug_botan_inc = os.path.join(debug_botan_path, "include")
            if not os.path.exists(os.path.join(debug_botan_inc,
                                               "botan\\init.h")):
                print >> sys.stderr, "can't find debug Botan includes"
                sys.exit(1)
            varvals["DEBUGINCPATH"] = debug_botan_inc
            if not os.path.exists(os.path.join(debug_botan_path, "botan.lib")):
                print >> sys.stderr, "can't find debug Botan library"
                sys.exit(1)
            varvals["DEBUGLIBPATH"] = debug_botan_path
        else:
            varvals["DEBUGDLLPATH"] = varvals["DLLPATH"]
            varvals["DEBUGINCPATH"] = varvals["INCLUDEPATH"]
            varvals["DEBUGLIBPATH"] = varvals["LIBPATH"]

        # Botan version
        if verbose:
            print "checking Botan version"
        botan_version_minor = 0
        system_libs = []
        if os.path.exists(botan_dll):
            subprocess.call(["copy", botan_dll, "."], shell=True)
        else:
            system_libs = ["user32.lib", "advapi32.lib"]
        inc = botan_inc
        lib = os.path.join(botan_path, "botan.lib")
        testfile = open("testbotan.cpp", "w")
        print >>testfile, '\
#include <botan/init.h>\n\
#include <botan/version.h>\n\
int main() {\n\
 using namespace Botan;\n\
 LibraryInitializer::initialize();\n\
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,10,0)\n\
 return 1;\n\
#endif\n\
#if BOTAN_VERSION_CODE > BOTAN_VERSION_CODE_FOR(1,11,0)\n\
 return 2;\n\
#endif\n\
 return 0;\n\
}'
        testfile.close()
        command = ["cl", "/nologo", "/MD", "/I", inc, "testbotan.cpp", lib]
        command.extend(system_libs)
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        if not os.path.exists(".\\testbotan.exe"):
            print >> sys.stderr, "can't create .\\testbotan.exe"
            sys.exit(1)
        ret = subprocess.call(".\\testbotan.exe")
        if ret == 1:
            print >> sys.stderr, "Botan version too old"
            sys.exit(1)
        if ret == 2:
            botan_version_minor = 11
            print >> sys.stderr, "Botan version 11 not yet supported"
            sys.exit(1)
        if ret != 0:
            print >> sys.stderr, "Botan test failed"
            sys.exit(1)
        else:
            botan_version_minor = 10

        # Botan ECC support
        if enable_ecc:
            if verbose:
                print "checking Botan ECC support"
            testfile = open("testecc.cpp", "w")
            print >>testfile, '\
#include <botan/init.h>\n\
#include <botan/ec_group.h>\n\
#include <botan/oids.h>\n\
int main() {\n\
 Botan::LibraryInitializer::initialize();\n\
 const std::string name("secp256r1");\n\
 const Botan::OID oid(Botan::OIDS::lookup(name));\n\
 const Botan::EC_Group ecg(oid);\n\
 try {\n\
  const Botan::SecureVector<Botan::byte> der =\n\
   ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);\n\
 } catch(...) {\n\
  return 1;\n\
 }\n\
 return 0;\n\
}'
            testfile.close()
            command = ["cl", "/nologo", "/MD", "/I", inc, "testecc.cpp", lib]
            command.extend(system_libs)
            subprocess.check_output(command, stderr=subprocess.STDOUT)
            if not os.path.exists(".\\testecc.exe"):
                print >> sys.stderr, "can't create .\\testecc.exe"
                sys.exit(1)
            if subprocess.call(".\\testecc.exe") != 0:
                print >> sys.stderr, \
                    "can't find P256: upgrade to Botan >= 1.10.6"
                sys.exit(1)

        # Botan GOST support
        if enable_gost:
            if verbose:
                print "checking Botan GOST support"
            testfile = open("testgost.cpp", "w")
            print >>testfile, '\
#include <botan/init.h>\n\
#include <botan/gost_3410.h>\n\
#include <botan/oids.h>\n\
int main() {\n\
 Botan::LibraryInitializer::initialize();\n\
 const std::string name("gost_256A");\n\
 const Botan::OID oid(Botan::OIDS::lookup(name));\n\
 const Botan::EC_Group ecg(oid);\n\
 try {\n\
  const Botan::SecureVector<Botan::byte> der =\n\
   ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);\n\
 } catch(...) {\n\
  return 1;\n\
 }\n\
 return 0;\n\
}'
            testfile.close()
            command = ["cl", "/nologo", "/MD", "/I", inc, "testgost.cpp", lib]
            command.extend(system_libs)
            subprocess.check_output(command, stderr=subprocess.STDOUT)
            if not os.path.exists(".\\testgost.exe"):
                print >> sys.stderr, "can't create .\\testgost.exe"
                sys.exit(1)
            if subprocess.call(".\\testgost.exe") != 0:
                print >> sys.stderr, \
                    "can't find GOST: upgrade to Botan >= 1.10.6"
                sys.exit(1)

        # no check for Botan RFC3394 support
        condvals["RFC3394"] = True

        # Botan RFC5649 support
        if verbose:
            print "checking Botan RFC5649 support"
        testfile = open("testrfc5649.cpp", "w")
        print >>testfile, '\
#include <botan/botan.h>\n\
#include <botan/rfc3394.h>\n\
int main() {\n\
 using namespace Botan;\n\
 SecureVector<byte> key(10);\n\
 SymmetricKey kek("AABB");\n\
 Algorithm_Factory& af = global_state().algorithm_factory();\n\
 SecureVector<byte> x = rfc5649_keywrap(key, kek, af);\n\
 return 1;\n\
}'
        testfile.close()
        command = ["cl", "/nologo", "/MD", "/I", inc, "testrfc5649.cpp", lib]
        command.extend(system_libs)
        subprocess.call(command)
        if not os.path.exists(".\\testrfc5649.exe"):
            if verbose:
                print "Found AES key wrap with pad"
            condvals["RFC5649"] = True
        else:
            if verbose:
                print "can't compile Botan AES key wrap with pad"

        # Botan GNU MP support
        if botan_version_minor == 10:
            if verbose:
                print "checking Botan GNU MP support"
            testfile = open("testgnump.cpp", "w")
            print >>testfile, '\
#include <botan/build.h>\n\
int main() {\n\
#ifndef BOTAN_HAS_ENGINE_GNU_MP\n\
#error "No GNU MP support";\n\
#endif\n\
}'
            testfile.close()
            command = ["cl", "/nologo", "/MD", "/I", inc, "testgnump.cpp", lib]
            command.extend(system_libs)
            subprocess.call(command)
            if not os.path.exists(".\\testgnump.exe"):
                if verbose:
                    print "Botan GNU MP is supported"
            else:
                if verbose:
                    print "Botan GNU MP is not supported"

    else:

        condvals["OPENSSL"] = True
        varvals["LIBNAME"] = "libeay32.lib"
        varvals["EXTRALIBS"] = "crypt32.lib;"
        openssl_path = os.path.abspath(openssl_path)
        openssl_dll = os.path.join(openssl_path, "bin\\libeay32.dll")
        varvals["DLLPATH"] = openssl_dll
        openssl_inc = os.path.join(openssl_path, "include")
        if not os.path.exists(os.path.join(openssl_inc, "openssl\\ssl.h")):
            print >> sys.stderr, "can't find OpenSSL headers"
            sys.exit(1)
        varvals["INCLUDEPATH"] = openssl_inc
        openssl_lib = os.path.join(openssl_path, "lib")
        if not os.path.exists(os.path.join(openssl_lib, "libeay32.lib")):
            print >> sys.stderr, "can't find OpenSSL library"
            sys.exit(1)
        varvals["LIBPATH"] = openssl_lib
        if enable_debug:
            debug_openssl_path = os.path.abspath(debug_openssl_path)
            varvals["DEBUGDLLPATH"] = \
                os.path.join(debug_openssl_path, "bin\\libeay32.dll")
            debug_openssl_inc = os.path.join(debug_openssl_path, "include")
            if not os.path.exists(os.path.join(debug_openssl_inc,
                                               "openssl\\ssl.h")):
                print >> sys.stderr, "can't find debug OpenSSL headers"
                sys.exit(1)
            varvals["DEBUGINCPATH"] = debug_openssl_inc
            debug_openssl_lib = os.path.join(debug_openssl_path, "lib")
            if not os.path.exists(os.path.join(debug_openssl_lib,
                                               "libeay32.lib")):
                print >> sys.stderr, "can't find debug OpenSSL library"
                sys.exit(1)
            varvals["DEBUGLIBPATH"] = debug_openssl_lib
        else:
            varvals["DEBUGDLLPATH"] = varvals["DLLPATH"]
            varvals["DEBUGINCPATH"] = varvals["INCLUDEPATH"]
            varvals["DEBUGLIBPATH"] = varvals["LIBPATH"]

        # OpenSSL support
        if verbose:
            print "checking OpenSSL"
        system_libs = []
        if os.path.exists(openssl_dll):
            subprocess.call(["copy", openssl_dll, "."], shell=True)
        else:
            system_libs = ["user32.lib", "advapi32.lib", "gdi32.lib", "crypt32.lib"]
        inc = openssl_inc
        lib = os.path.join(openssl_lib, "libeay32.lib")
        testfile = open("testossl.c", "w")
        print >>testfile, '\
#include <openssl/err.h>\n\
int main() {\n\
 ERR_clear_error();\n\
 return 0;\n\
}'
        testfile.close()
        command = ["cl", "/nologo", "/MD", "/I", inc, "testossl.c", lib]
        command.extend(system_libs)
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        if not os.path.exists(".\\testossl.exe"):
            print >> sys.stderr, "can't create .\\testossl.exe"
            sys.exit(1)
        if subprocess.call(".\\testossl.exe") != 0:
            print >> sys.stderr, "OpenSSL test failed"
            sys.exit(1)

        # OpenSSL version
        if verbose:
            print "checking OpenSSL version"
        testfile = open("testosslv.c", "w")
        print >>testfile, '\
#include <openssl/ssl.h>\n\
#include <openssl/opensslv.h>\n\
int main() {\n\
#ifndef OPENSSL_VERSION_NUMBER\n\
 return -1;\n\
#endif\n\
#if OPENSSL_VERSION_NUMBER >= 0x010000000L\n\
 return 0;\n\
#else\n\
 return 1;\n\
#endif\n\
}'
        testfile.close()
        command = ["cl", "/nologo", "/MD", "/I", inc, "testosslv.c", lib]
        command.extend(system_libs)
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        if not os.path.exists(".\\testosslv.exe"):
            print >> sys.stderr, "can't create .\\testosslv.exe"
            sys.exit(1)
        if subprocess.call(".\\testosslv.exe") != 0:
            print >> sys.stderr, \
                "OpenSLL version too old (1.0.0 or later required)"
            sys.exit(1)

        # OpenSSL ECC support
        if enable_ecc:
            if verbose:
                print "checking OpenSSL ECC support"
            testfile = open("testecc.c", "w")
            print >>testfile, '\
#include <openssl/ecdsa.h>\n\
#include <openssl/objects.h>\n\
int main() {\n\
 EC_KEY *ec256, *ec384;\n\
 ec256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n\
 ec384 = EC_KEY_new_by_curve_name(NID_secp384r1);\n\
 if (ec256 == NULL || ec384 == NULL)\n\
  return 1;\n\
 return 0;\n\
}'
            testfile.close()
            command = ["cl", "/nologo", "/MD", "/I", inc, "testecc.c", lib]
            command.extend(system_libs)
            subprocess.check_output(command, stderr=subprocess.STDOUT)
            if not os.path.exists(".\\testecc.exe"):
                print >> sys.stderr, "can't create .\\testecc.exe"
                sys.exit(1)
            if subprocess.call(".\\testecc.exe") != 0:
                print >> sys.stderr, "can't find P256 or P384: no ECC support"
                sys.exit(1)

        # OpenSSL GOST support
        if enable_gost:
            if verbose:
                print "checking OpenSSL GOST support"
            testfile = open("testgost.c", "w")
            print >>testfile, '\
#include <openssl/conf.h>\n\
#include <openssl/engine.h>\n\
int main() {\n\
 ENGINE *e;\n\
 EC_KEY *ek;\n\
 ek = NULL;\n\
 OPENSSL_config(NULL);\n\
 e = ENGINE_by_id("gost");\n\
 if (e == NULL)\n\
  return 1;\n\
 if (ENGINE_init(e) <= 0)\n\
  return 1;\n\
 return 0;\n\
}'
            testfile.close()
            command = ["cl", "/nologo", "/MD", "/I", inc, "testgost.c", lib]
            command.extend(system_libs)
            subprocess.check_output(command, stderr=subprocess.STDOUT)
            if not os.path.exists(".\\testgost.exe"):
                print >> sys.stderr, "can't create .\\testgost.exe"
                sys.exit(1)
            if subprocess.call(".\\testgost.exe") != 0:
                print >> sys.stderr, "can't find GOST: no GOST support"
                sys.exit(1)

        # OpenSSL EVP interface for AES key wrapping (aka RFC 3394)
        if verbose:
            print "checking OpenSSL EVP interface for AES key wrapping"
        testfile = open("testrfc3394.c", "w")
        print >>testfile, '\
#include <openssl/evp.h>\n\
int main() {\n\
 EVP_aes_128_wrap();\n\
 return 1;\n\
}'
        testfile.close()
        command = ["cl", "/nologo", "/MD", "/I", inc, "testrfc3394.c", lib]
        command.extend(system_libs)
        subprocess.call(command)
        if os.path.exists(".\\testrfc3394.exe"):
            if verbose:
                print "RFC 3394 is supported"
            condvals["RFC3394"] = True
        else:
            if verbose:
                print "can't compile OpenSSL RFC 3394"

        # OpenSSL EVP interface for AES key wrap with pad (aka RFC 5649)
        if verbose:
            print "checking OpenSSL EVP interface for AES key wrapping with pad"
        testfile = open("testrfc5649.c", "w")
        print >>testfile, '\
#include <openssl/evp.h>\n\
int main() {\n\
 EVP_aes_128_wrap_pad();\n\
 return 1;\n\
}'
        testfile.close()
        command = ["cl", "/nologo", "/MD", "/I", inc, "testrfc5649.c", lib]
        command.extend(system_libs)
        subprocess.call(command)
        if os.path.exists(".\\testrfc5649.exe"):
            if verbose:
                print "RFC 5649 is supported"
            condvals["RFC5649"] = True
        else:
            if verbose:
                print "can't compile OpenSSL RFC 5649"
        
    # configure CppUnit
    if want_tests:
        condvals["TESTS"] = True
        cppunit_path = os.path.abspath(cppunit_path)
        cppunit_inc = os.path.join(cppunit_path, "include")
        if not os.path.exists(os.path.join(cppunit_inc, "cppunit\\Test.h")):
            print >> sys.stderr, "can't find CppUnit headers"
            sys.exit(1)
        varvals["CUINCPATH"] = cppunit_inc
        cppunit_lib = os.path.join(cppunit_path, "lib")
        if not os.path.exists(os.path.join(cppunit_lib, "cppunit.lib")):
            cppunit_lib = cppunit_path
        if not os.path.exists(os.path.join(cppunit_lib, "cppunit.lib")):
            print >> sys.stderr, "can't find CppUnit library"
            sys.exit(1)
        if enable_debug:
            if not os.path.exists(os.path.join(cppunit_lib, "cppunitd.lib")):
                print >> sys.stderr, "can't find debug CppUnit library"
                sys.exit(1)
        varvals["CULIBPATH"] = cppunit_lib

    # misc
    if enable_non_paged:
        condvals["NONPAGE"] = True

def kw(path):
    """escape spaces"""
    if re.search(r' ', path):
        return '"' + path + '"'
    else:
        return path

def setupfile(filename):
    """setup files with condition stacks and variable expansions"""
    cond = "@@@"
    conds = []
    passing = True
    passes = []
    filein = open(filename + ".in", "r")
    fileout = open(filename, "w")

    for line in filein:
        line = line.rstrip("\r\n")
        cif = re.match(r'@IF (.*)', line)
        if cif:
            conds.append(cond)
            passes.append(passing)
            cond = cif.group(1)
            if condvals.get(cond):
                # do nothing
                pass
            else:
                passing = False
            continue
        celse = re.match(r'@ELSE (.*)', line)
        if celse:
            if cond != celse.group(1):
                raise SyntaxError("@ELSE " + celse.group(1) +
                                  " mismatch in " + filename)
            if condvals.get(cond):
                passing = False
            else:
                if len(passes) > 0:
                    passing = passes[-1]
                else:
                    passing = True
            continue
        cend = re.match(r'@END (.*)', line)
        if cend:
            if cond != cend.group(1):
                raise SyntaxError("@END " + cend.group(1) +
                                  " mismatch in " + filename)
            cond = conds.pop()
            if len(passes) > 0:
                passing = passes.pop()
            else:
                passing = True
            continue
        if not passing:
            continue
        while True:
            vm = re.match(r'([^@]*)@([^@ ]*)@(.*)', line)
            if vm:
                if vm.group(2) in varnames:
                    if varvals.get(vm.group(2)):
                        val = kw(varvals[vm.group(2)])
                    else:
                        val = ""
                    line = vm.group(1) + val + vm.group(3)
                    continue
                else:
                    raise SyntaxError("unknown control @" + vm.group(2) +
                                      "@ in " + filename)
            break
        print >>fileout, line
    if verbose:
        print "Setting up " + filename
    filein.close()
    fileout.close()

def main(args):
    """run it"""

    # no arguments -> usage
    if len(args) <= 1:
        for line in usage:
            print line
        sys.exit(1)

    parseargs(args[1:])

    if want_help:
        dohelp()
    if want_clean:
        doclean()
    if want_unknown:
        dounknown()

    # status before config

    if verbose:
        if enable_keep:
            print "keep: enabled"
        else:
            print "keep: disabled"
        if platform == 64:
            print "64bit: enabled"
        else:
            print "64bit: disabled"
        if enable_debug:
            print "debug: enabled"
        else:
            print "debug: disabled"
        if enable_ecc:
            print "ecc: enabled"
        else:
            print "ecc: disabled"
        if enable_gost:
            print "gost: enabled"
        else:
            print "gost: disabled"
        if enable_non_paged:
            print "non-paged-memory: enabled"
        else:
            print "non-paged-memory: disabled"
        print "crypto-backend: " + crypto_backend
        if crypto_backend == "botan":
            print "botan-path: " + botan_path
            if enable_debug:
                print "debug-botan-path: " + debug_botan_path
        else:
            print "openssl-path: " + openssl_path
            if enable_debug:
                print "debug-openssl-path: " + debug_openssl_path
        if want_tests:
            print "cppunit-path: " + cppunit_path

    doconfig()

    # status after config

    if verbose:
        print "Configuration Status"
        print "\tconditions:"
        for name in condnames:
            if condvals.get(name):
                print "\t\t" + name + " is true"
            else:
                print "\t\t" + name + " is false"
        print "\tsubstitutions:"
        for name in varnames:
            if varvals.get(name):
                print "\t\t" + name + '-> "' + varvals[name] + '"'
        print

    for filename in filelist:
        setupfile(filename)

    # clean test file
    if not enable_keep:
        cleantest()

    print "Configured."
    sys.exit(0)

main(sys.argv)

# Notes: Unix configure.ac options
#  --enable-64bit supported
#  --enable-ecc supported
#  --enable-gost supported
#  --enable-non-paged-memory supported
#  --enable-visibility (enforced by DLLs)
#  --with-crypto-backend supported
#  --with-botan supported (Release and Debug)
#  --with-openssl supported (Release and Debug)
#  --with-migrate (useless as SoftHSMv1 is not supported)
#  --with-objectstore-backend-db (TODO)
#  --with-sqlite3 (useless until objectstore backend can be chosen)
