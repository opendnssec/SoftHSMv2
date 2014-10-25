#!python

# Configure -- python version
#
# this script builds Visual Studio files

import sys
import os
import os.path
import re

# files to configure

filelist = [ "config.h",
             "softhsm2.sln",
             "convarch\\convarch.vcxproj.filters",
             "convarch\\convarch.vcxproj",
             "cryptotest\\cryptotest.vcxproj",
             "datamgrtest\\datamgrtest.vcxproj",
             "handlemgrtest\\handlemgrtest.vcxproj",
             "keyconv\\keyconv.vcxproj.filters",
             "keyconv\\keyconv.vcxproj",
             "objstoretest\\objstoretest.vcxproj",
             "p11test\\p11test.vcxproj",
             "sessionmgrtest\\sessionmgrtest.vcxproj",
             "slotmgrtest\\slotmgrtest.vcxproj",
             "softhsm2\\softhsm2.vcxproj",
             "util\\util.vcxproj.filters",
             "util\\util.vcxproj" ]

# variables to expand

varvals = {}

varnames = [ "DLLPATH",
             "INCLUDEPATH",
             "LIBPATH",
             "PLATFORM",
             "PLATFORMDIR" ]

# conditions to stack

condvals = {}

condnames = [ "BOTAN",
              "OPENSSL",
              "TESTS" ]

# enable-xxx/disable-xxx arguments

enablelist = [ "debug",
               "ecc",
               "gost" ]

# with-xxx/without-xxx arguments

withlist = [ "botan",
             "cppunit",
             "crypto-backend",
             "loglevel",
             "openssl",
             "platform" ]

# general arguments

optionlist = [ "help", "verbose", "clean" ]

# usage

usage = [ "Usage: perl Configure.pl help",
          "       perl Configure.pl options*",
          "       perl Configure.pl clean" ]

# help

help = [
"'perl Configure.pl' configures SoftHSMv2 build files.\n",
usage,
"\nGeneral Options and Commands:",
"  verbose             (options) print messages",
"  help                (command) print this help",
"  clean               (command) clean up generated files",
"  <none>              (command) print a summary of the configuration",
"\nOptional Features:",
"  enable-debug        enable build of Debug config [default=yes]",
"  enable-ecc          enable support for ECC [default=yes]",
"  enable-gost         enable support for GOST [default=yes]",
"\nRequired Packages:",
"  with-platform       select the platform [win32|x64]",
"  with-crypto-backend select the crypto backend [botan|openssl]",
"\nOptional Packages:",
"  with-botan=PATH     speficy prefix of path of Botan",
"  with-openssl=PATH   speficy prefix of path of OpenSSL",
"  with-cppunit=PATH   specify prefix of path of CppUnit",
"  with-loglevel=INT   the log level [0..4] [default=3]" ]

# variables for parsing

configargs = None
verbose = 0
want_help = False
want_clean = False
want_unknown = False
unknown_value = None
enable_debug = True
enable_ecc = True
enable_gost = True
platform = None
crypto_backend = None
botan_path = "..\\..\\btn"
debug_botan_path = "..\\..\\btn_d"
openssl_path = "..\\..\\ssl"
debug_openssl_path = "..\\..\\ssl_d"
want_tests = True
cppunit_path = "..\\..\\cu"
loglevel = 3

def parseargs(args):
    """parse arguments"""
    global verbose
    global want_help
    global want_clean
    global want_unknown
    global unknown_value
    for arg in args:
        if arg.lower() == "verbose":
            verbose = 1
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
        debug_botan_path = botan_path + "_d"
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
    global enable_debug
    global enable_ecc
    global enable_gost
    global want_unknown
    global unknown_value
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
    want_unknown = True
    if not val:
        unknown_value = "disable-" + key
    else:
        unknown_value = "enable-" + key

def mywith(key, val, detail = None):
    """parse with/without"""
    global platform
    global crypto_backend
    global botan_path
    global openssl_path
    global cppunit_path
    global loglevel
    global want_unknown
    global unknown_value
    if key.lower() == "platform":
        if val and (detail.lower() == "win32"):
            platform = "win32"
            return
        if val and (detail.lower() == "x64"):
            platform = "x64"
            return
        want_unknown = True
        unknown_value = "with-platform=" + detail
        return
    if key.lower() == "crypto-backend":
        if val and (detail.lower() == "botan"):
            crypto_backend = "botan"
            return
        if val and (detail.lower() == "openssl"):
            crypto_backend = "openssl"
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
    if key.lower() == "openssl":
        if not val:
            want_unknown = True
            unknown_value = "without-openssl doesn't make sense"
            return
        if detail.lower() != "yes":
            openssl_path = detail
        return
    if key.lower() == "cppunit":
        if not val:
            want_tests = False
            return
        if detail.lower() != "yes":
            cppunit_path = detail
        return
    if key.lower() == "loglevel":
        if not val:
            want_unknown = True
            unknown_value = "without-loglevel doesn't make sense"
            return
        if detail:
            if detail ==  "0":
                loglevel = 0
                return
            if detail ==  "1":
                loglevel = 1
                return
            if detail ==  "2":
                loglevel = 2
                return
            if detail ==  "3":
                loglevel = 3
                return
            if detail ==  "4":
                loglevel = 4
                return
            want_unknown = True
            unknown_value = "with-loglevel=" + detail
            return
        return
    want_unknown = True
    if not val:
        unknown_value = "without-" + key
    else:
        unknown_value = "with-" + key

def dohelp():
    """help"""
    global help
    for line in help:
        print line
    sys.exit(1)

def doclean():
    """clean"""
    global filelist
    for file in filelist:
        os.unlink(file)
    sys.exit(0)

def dounknown():
    """parsing error"""
    global unknown_value
    print >> sys.stderr, "can't parse " + unknown_value + ""
    sys.exit(1)

def doconfig():
    """config itself"""
    global platform
    global varvals
    global crypto_backend
    global condvals

    # configure the platform
    if platform == "win32":
        varvals["PLATFORM"] = "Win32"
    else:
        varvals["PLATFORM"] = "x64"
        varvals["PLATFORMDIR"] = "x64\\"

    # configure the crypto
    if crypto_backend == "botan":
        condvals["BOTAN"] = True
    else:
        condvals["OPENSSL"] = True

def kw(path):
    """escape spaces"""
    if re.search(r' ', path):
        return '"' + path + '"'
    else:
        return path

def setupfile(filename):
    """setup files with condition stacks and variable expansions"""
    global condvals
    global varvals
    global varnames
    global verbose
    cond = "@@@"
    conds = []
    pass_ = 1
    passes = []
    filein = open(filename + ".in", "r")
    fileout = open(filename, "w")

    for line in filein:
        line = line.rstrip("\r\n")
        cif = re.match(r'@IF (.*)', line)
        if cif:
            conds.append(cond)
            passes.append(pass_)
            cond = cif.group(1)
            if condvals.get(cond):
                # do nothing
                pass
            else:
                pass_ = 0
            continue
        celse = re.match(r'@ELSE (.*)', line)
        if celse:
            if cond != celse.group(1):
                raise SyntaxError("@ELSE " + celse.group(1) +
                                  " mismatch in " + filename)
            if condvals.get(cond):
                pass_ = 0
            else:
                if len(conds) > 0:
                    pass_ = passes[0]
                else:
                    pass_ = 1
            continue
        cend = re.match(r'@END (.*)', line)
        if cend:
            if cond != cend.group(1):
                raise SyntaxError("@END " + cend.group(1) +
                                  " mismatch in " + filename)
            cond = conds.pop()
            if len(passes) > 0:
                pass_ = passes.pop()
            else:
                pass_ = 1
            continue
        if pass_ == 0:
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
    global usage
    global filelist
    global condnames
    global condvals
    global varnames
    global varvals
    global want_help
    global want_clean
    global want_unknown
    global platform
    global crypto_backend
    global enable_debug
    global enable_ecc
    global enable_gost
    global botan_path
    global debug_botan_path
    global openssl_path
    global debug_openssl_path
    global want_tests
    global cppunit_path
    global loglevel

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

    # required

    if platform is None:
        print >> sys.stderr, "with-platform=[win32|x64] is REQUIRED"
        sys.exit(1)
    if crypto_backend is None:
        print >> sys.stderr, "with-crypto-backend=[botan|openssl] is REQUIRED"
        sys.exit(1)

    # status before config

    if verbose:
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
        print "platform: " + platform
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
        print "loglevel: " + str(loglevel)

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

    for file in filelist:
        setupfile(file)
    print "Configured."
    sys.exit(0)

main(sys.argv)
