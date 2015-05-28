#!perl

# Configure -- perl version
#
# this script builds Visual Studio files

require 5.000;
use strict;
use File::Spec;
use Cwd;

# files to configure

my @filelist = ("config.h",
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
                "util\\util.vcxproj");

# test files

my @testlist = ("botan",
                "ecc",
                "gnump",
                "gost",
                "ossl",
                "osslv",
                "rfc3394",
                "rfc5649");

# variables to expand

my %varvals;

my @varnames = ("CUINCPATH",
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
                "PLATFORMDIR");

# conditions to stack

my %condvals;

my @condnames = ("BOTAN",
                 "ECC",
                 "GOST",
                 "NONPAGE",
                 "OPENSSL",
                 "RFC3394",
                 "RFC5649",
                 "TESTS");

# enable-xxx/disable-xxx arguments

my @enablelist = ("64bit",
                  "debug",
                  "ecc",
                  "gost",
                  "keep",
                  "non-paged-memory",
                  "verbose");

# with-xxx/without-xxx arguments

my @withlist = ("botan",
                "cppunit",
                "crypto-backend",
                "debug-botan",
                "debug-openssl",
                "openssl");

# general commands

my @commandlist = ("help", "clean"); # verbose, keep

# usage

my @usage = ("Usage: perl Configure.pl help\n",
             "       perl Configure.pl options*\n",
             "       perl Configure.pl clean\n");

# help

my @help = (
"'perl Configure.pl' configures SoftHSMv2 build files.\n\n",
@usage,
"\nGeneral Commands:\n",
"  help                     print this help\n",
"  clean                    clean up generated files\n",
"  <none>                   print a summary of the configuration\n",
"\nOptional Features:\n",
"  enable-verbose           print messages [default=no]\n",
"  enable-keep              keep test files after config [default=no]\n",
"  enable-64bit             enable 64-bit compiling [default=no]\n",
"  enable-debug             enable build of Debug config [default=yes]\n",
"  enable-ecc               enable support for ECC [default=yes]\n",
"  enable-gost              enable support for GOST [default=yes]\n",
"  enable-non-paged-memory  enable non-paged memory [default=yes]\n",
"\nOptional Packages:\n",
"  with-crypto-backend      select the crypto backend [openssl|botan]\n",
"  with-botan=PATH          speficy prefix of path of Botan (Release)\n",
"  with-debug-botan=PATH    speficy prefix of path of Botan (Debug)\n",
"  with-openssl=PATH        speficy prefix of path of OpenSSL (Release)\n",
"  with-debug-openssl=PATH  speficy prefix of path of OpenSSL (Debug)\n",
"  with-cppunit=PATH        specify prefix of path of CppUnit\n");

# variables for parsing

my $verbose = 0;
my $configargs;
my $want_help = "no";
my $want_clean = "no";
my $want_unknown = "no";
my $unknown_value;
my $enable_keep = "no";
my $enable_debug = "yes";
my $enable_ecc = "yes";
my $enable_gost = "yes";
my $enable_non_paged = "yes";
my $platform = "win32";
my $crypto_backend = "openssl";
my $botan_path = "..\\..\\btn";
my $debug_botan_path;
my $openssl_path = "..\\..\\ssl";
my $debug_openssl_path;
my $want_tests = "yes";
my $cppunit_path = "..\\..\\cu";

# no arguments -> usage

if ($#ARGV < 0) {
    foreach (@usage) {
        print $_;
    }
    exit 1;
}

# parse arguments

foreach (@ARGV) {
    if (/^verbose$/i) {
        $verbose = 1;
    } elsif (/^keep$/i) {
        appargs($_);
        $enable_keep = "yes";
    } elsif (/^help$/i) {
        $want_help = "yes";
    } elsif (/^disable-(.*)$/i) {
        appargs($_);
        myenable($1, "no");
    } elsif (/^enable-(.*)$/i) {
        appargs($_);
        myenable($1, "yes");
    } elsif (/^without-(.*)$/i) {
        appargs($_);
        mywith($1, "no");
    } elsif (/^with-(.*)=(.*)$/i) {
        appargs($_);
        mywith($1, $2);
    } elsif (/^with-(.*)$/i) {
        appargs($_);
        mywith($1, "yes");
    } elsif (/^clean$/i) {
        $want_clean = "yes";
    } else {
        $want_unknown = "yes";
        $unknown_value = $_;
    }
}

# append seen arguments to configargs

sub appargs {
    my $arg = $_[0];
    # escape backslashes, spaces and double quotes
    $arg =~ s/([\\ "])/\\$1/g;
    if (defined($configargs)) {
        $configargs .= " " . $arg;
    } else {
        $configargs = $arg;
    }
}

# parse enable/disable

sub myenable {
    my $key = $_[0];
    my $val = $_[1];

    if ($key =~ /^64bit$/i) {
        if ($val =~ /^yes$/i) {
            $platform = "x64";
        }
    } elsif ($key =~ /^debug$/i) {
        if ($val =~ /^no$/i) {
            $enable_debug = "no";
        }
    } elsif ($key =~ /^ecc$/i) {
        if ($val =~ /^no$/i) {
            $enable_ecc = "no";
        }
    } elsif ($key =~ /^gost$/i) {
        if ($val =~ /^no$/i) {
            $enable_gost = "no";
        }
    } elsif ($key =~ /^non-paged-memory$/i) {
        if ($val =~ /^no$/i) {
            $enable_non_paged = "no";
        }
    } elsif ($key =~ /^keep$/i) {
        if ($val =~ /^yes$/i) {
            $enable_keep = "yes";
        }
    } elsif ($key =~ /^verbose$/i) {
        if ($val =~ /^yes$/i) {
            $verbose = 1;
        }
    } else {
        $want_unknown = "yes";
        if ($val eq "no") {
            $unknown_value = "disable-" . $key;
        } else {
            $unknown_value = "enable-" . $key;
        }
    }
}

# parse with/without

sub mywith {
    my $key = $_[0];
    my $val = $_[1];

    if ($key =~ /^crypto-backend$/i) {
        if ($val =~ /^openssl$/i) {
            $crypto_backend = "openssl";
        } elsif ($val =~ /^botan$/i) {
            $crypto_backend = "botan";
        } else {
            $want_unknown = "yes";
            $unknown_value = "with-crypto-backend=" . $val;
        }
    } elsif ($key =~ /^botan$/i) {
        if ($val =~ /^no$/i) {
            $want_unknown = "yes";
            $unknown_value = "without-botan doesn't make sense\n";
        } elsif ($val !~ /^yes$/i) {
            $botan_path = $val;
        }
    } elsif ($key =~ /^debug-botan$/i) {
        if ($val =~ /^no$/i) {
            $want_unknown = "yes";
            $unknown_value = "without-debug-botan doesn't make sense\n";
        } elsif ($val !~ /^yes$/i) {
            $debug_botan_path = $val;
        }
    } elsif ($key =~ /^openssl$/i) {
        if ($val =~ /^no$/i) {
            $want_unknown = "yes";
            $unknown_value = "without-openssl doesn't make sense\n";
        } elsif ($val !~ /^yes$/i) {
            $openssl_path = $val;
        }
    } elsif ($key =~ /^debug-openssl$/i) {
        if ($val =~ /^no$/i) {
            $want_unknown = "yes";
            $unknown_value = "without-debug-openssl doesn't make sense\n";
        } elsif ($val !~ /^yes$/i) {
            $debug_openssl_path = $val;
        }
    } elsif ($key =~ /^cppunit$/i) {
        if ($val =~ /^no$/i) {
            $want_tests = "no";
        } elsif ($val !~ /^yes$/i) {
            $cppunit_path = $val;
        }
    } else {
        $want_unknown = "yes";
        if ($val eq "no") {
            $unknown_value = "without-" . $key;
        } else {
            $unknown_value = "with-" . $key;
        }
    }
}

# help

if ($want_help ne "no") {
    foreach (@help) {
        print $_;
    }
    exit 1;
}

# clean

sub cleantest {
    my $file;
    foreach $file (@testlist) {
        unlink("test" . $file . ".c");
        unlink("test" . $file . ".cpp");
        unlink("test" . $file . ".obj");
        unlink("test" . $file . ".exe");
    }
    unlink("botan.dll");
    unlink("libeay32.dll");
}

if ($want_clean eq "yes") {
    my $file;
    cleantest();
    foreach $file (@filelist) {
        unlink($file);
    }
    exit 0;
}

# parsing error

if ($want_unknown ne "no") {
    print STDERR "can't parse $unknown_value\n";
    exit 1;
}

# debug

if ($enable_debug eq "yes") {
    if (!defined($debug_botan_path)) {
        $debug_botan_path = $botan_path . "_d";
    }
    if (!defined($debug_openssl_path)) {
        $debug_openssl_path = $openssl_path . "_d";
    }
}

# verbose

if ($verbose) {
    if ($enable_keep eq "yes") {
        print "keep: enabled\n";
    } else {
        print "keep: disabled\n";
    }
    if ($platform eq "x64") {
        print "64bit: enabled\n";
    } else {
        print "64bit: disabled\n";
    }
    if ($enable_debug eq "yes") {
        print "debug: enabled\n";
    } else {
        print "debug: disabled\n";
    }
    if ($enable_ecc eq "yes") {
        print "ecc: enabled\n";
    } else {
        print "ecc: disabled\n";
    }
    if ($enable_gost eq "yes") {
        print "gost: enabled\n";
    } else {
        print "gost: disabled\n";
    }
    if ($enable_non_paged eq "yes") {
        print "non-paged-memory: enabled\n";
    } else {
        print "non-paged-memory: disabled\n";
    }
    print "crypto-backend: $crypto_backend\n";
    if ($crypto_backend eq "botan") {
        print "botan-path: $botan_path\n";
        if ($enable_debug eq "yes") {
            print "debug-botan-path: $debug_botan_path\n";
        }
    } else {
        print "openssl-path: $openssl_path\n";
        if ($enable_debug eq "yes") {
            print "debug-openssl-path: $debug_openssl_path\n";
        }
    }
    if ($want_tests eq "yes") {
        print "cppunit-path: $cppunit_path\n";
    }
}

# configure the platform

if ($platform eq "win32") {
    $varvals{"PLATFORM"} = "Win32";
} else {
    $varvals{"PLATFORM"} = "x64";
    $varvals{"PLATFORMDIR"} = "x64\\";
}

# configure ECC and GOST

if ($enable_ecc eq "yes") {
    $condvals{"ECC"} = 1;
}
if ($enable_gost eq "yes") {
    $condvals{"GOST"} = 1;
}

# configure the crypto

if ($crypto_backend eq "botan") {
    $condvals{"BOTAN"} = 1;
    $varvals{"LIBNAME"} = "botan.lib";
    $botan_path = File::Spec->rel2abs($botan_path);
    my $botan_dll = File::Spec->catfile($botan_path, "botan.dll");
    $varvals{"DLLPATH"} = $botan_dll;
    my $botan_inc = File::Spec->catfile($botan_path, "include");
    if (!-f File::Spec->catfile($botan_inc, "botan\\init.h")) {
        die "can't find Botan includes\n";
    }
    $varvals{"INCLUDEPATH"} = $botan_inc;
    if (!-f File::Spec->catfile($botan_path, "botan.lib")) {
        die "can't find Botan library\n";
    }
    $varvals{"LIBPATH"} = $botan_path;
    if ($enable_debug eq "yes") {
        $debug_botan_path = File::Spec->rel2abs($debug_botan_path);
        $varvals{"DEBUGDLLPATH"} =
            File::Spec->catfile($debug_botan_path, "botan.dll");
        my $debug_botan_inc =
            File::Spec->catfile($debug_botan_path, "include");
        if (!-f File::Spec->catfile($debug_botan_inc, "botan\\init.h")) {
            die "can't find debug Botan includes\n";
        }
        $varvals{"DEBUGINCPATH"} = $debug_botan_inc;
        if (!-f File::Spec->catfile($debug_botan_path, "botan.lib")) {
            die "can't find debug Botan library\n";
        }
        $varvals{"DEBUGLIBPATH"} = $debug_botan_path;
    } else {
        $varvals{"DEBUGDLLPATH"} = $varvals{"DLLPATH"};
        $varvals{"DEBUGINCPATH"} = $varvals{"INCLUDEPATH"};
        $varvals{"DEBUGLIBPATH"} = $varvals{"LIBPATH"};
    }

    # Botan version
    if ($verbose) {
        print "checking Botan version\n";
    }
    my $botan_version_minor = 0;
    my $system_libs = "";
    if (-f $botan_dll) {
        `copy "$botan_dll" .`;
    } else {
        $system_libs = " user32.lib advapi32.lib";
    }
    my $inc = $botan_inc;
    my $lib = File::Spec->catfile($botan_path, "botan.lib");
    open F, ">testbotan.cpp" || die $!;
    print F << 'EOF';
#include <botan/init.h>
#include <botan/version.h>
int main() {
 using namespace Botan;
 LibraryInitializer::initialize();
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,10,0)
 return 1;
#endif
#if BOTAN_VERSION_CODE > BOTAN_VERSION_CODE_FOR(1,11,0)
 return 2;
#endif
 return 0;
}
EOF
    close F;
    my $compret = `cl /nologo /MD /I "$inc" testbotan.cpp "$lib"$system_libs`;
    if (grep { -f and -x } ".\\testbotan.exe") {
        `.\\testbotan.exe`;
        if ($? == 1) {
            die "Botan version too old\n";
        } elsif ($? == 2) {
            $botan_version_minor = 11;
            die "Botan version 11 not yet supported\n";
        } elsif ($? != 0) {
            die "Botan test failed\n";
        } else {
            $botan_version_minor = 10;
        }
    } else {
        die "can't compile Botan test: $compret\n";
    }

    # Botan ECC support
    if ($enable_ecc eq "yes") {
        if ($verbose) {
            print "checking Botan ECC support\n";
        }
        open F, ">testecc.cpp" || die $!;
        print F << 'EOF';
#include <botan/init.h>
#include <botan/ec_group.h>
#include <botan/oids.h>
int main() {
 Botan::LibraryInitializer::initialize();
 const std::string name("secp256r1");
 const Botan::OID oid(Botan::OIDS::lookup(name));
 const Botan::EC_Group ecg(oid);
 try {
  const Botan::SecureVector<Botan::byte> der =
   ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
 } catch(...) {
  return 1;
 }
 return 0;
}
EOF
        close F;
        $compret = `cl /nologo /MD /I "$inc" testecc.cpp "$lib"$system_libs`;
        if (grep { -f and -x } ".\\testecc.exe") {
            `.\\testecc.exe`;
            if ($? != 0) {
                die "can't find P256: upgrade to Botan >= 1.10.6\n";
            }
        } else {
            die "can't compile ECC test: $compret\n";
        }
    }

    # Botan GOST support
    if ($enable_gost eq "yes") {
        if ($verbose) {
            print "checking Botan GOST support\n";
        }
        open F, ">testgost.cpp" || die $!;
        print F << 'EOF';
#include <botan/init.h>
#include <botan/gost_3410.h>
#include <botan/oids.h>
int main() {
 Botan::LibraryInitializer::initialize();
 const std::string name("gost_256A");
 const Botan::OID oid(Botan::OIDS::lookup(name));
 const Botan::EC_Group ecg(oid);
 try {
  const Botan::SecureVector<Botan::byte> der =
   ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
 } catch(...) {
  return 1;
 }
 return 0;
}
EOF
        close F;
        $compret = `cl /nologo /MD /I "$inc" testgost.cpp "$lib"$system_libs`;
        if (grep { -f and -x } ".\\testgost.exe") {
            `.\\testgost.exe`;
            if ($? != 0) {
                die "can't find GOST: upgrade to Botan >= 1.10.6\n";
            }
        } else {
            die "can't compile GOST test: $compret\n";
        }
    }

    # no check for Botan RFC3394 support
    $condvals{"RFC3394"} = 1;

    # Botan RFC5649 support
    if ($verbose) {
        print "checking Botan RFC5649 support\n";
    }
    open F, ">testrfc5649.cpp" || die $!;
    print F << 'EOF';
#include <botan/botan.h>
#include <botan/rfc3394.h>
int main() {
 using namespace Botan;
 SecureVector<byte> key(10);
 SymmetricKey kek("AABB");
 Algorithm_Factory& af = global_state().algorithm_factory();
 SecureVector<byte> x = rfc5649_keywrap(key, kek, af);
 return 1;
}
EOF
    close F;
    `cl /nologo /MD /I "$inc" testrfc5649.cpp "$lib"$system_libs`;
    if (grep { -f and -x } ".\\testrfc5649.exe") {
        if ($verbose) {
            print "Found AES key wrap with pad\n";
        }
        $condvals{"RFC5649"} = 1;
    } else {
        if ($verbose) {
            print "can't compile Botan AES key wrap with pad\n";
        }
    }

    # Botan GNU MP support
    if ($botan_version_minor == 10) {
        if ($verbose) {
            print "checking Botan GNU MP support\n";
        }
        open F, ">testgnump.cpp" || die $!;
        print F << 'EOF';
#include <botan/build.h>
int main() {
#ifndef BOTAN_HAS_ENGINE_GNU_MP
#error "No GNU MP support";
#endif
}
EOF
        close F;
        `cl /nologo /MD /I "$inc" testgnump.cpp "$lib"$system_libs`;
        if (grep { -f and -x } ".\\testgnump.exe") {
            if ($verbose) {
                print "Botan GNU MP is supported\n";
            }
        } else {
            if ($verbose) {
                print "Botan GNU MP is not supported\n";
            }
        }
    }

} else {

    $condvals{"OPENSSL"} = 1;
    $varvals{"LIBNAME"} = "libeay32.lib";
    $varvals{"EXTRALIBS"} = "crypt32.lib;";
    $openssl_path = File::Spec->rel2abs($openssl_path);
    my $openssl_dll = File::Spec->catfile($openssl_path, "bin\\libeay32.dll");
    $varvals{"DLLPATH"} = $openssl_dll;
    my $openssl_inc = File::Spec->catfile($openssl_path, "include");
    if (!-f File::Spec->catfile($openssl_inc, "openssl\\ssl.h")) {
        die "can't find OpenSSL headers\n";
    }
    $varvals{"INCLUDEPATH"} = $openssl_inc;
    my $openssl_lib = File::Spec->catfile($openssl_path, "lib");
    if (!-f File::Spec->catfile($openssl_lib, "libeay32.lib")) {
        die "can't find OpenSSL library\n";
    }
    $varvals{"LIBPATH"} = $openssl_lib;
    if ($enable_debug eq "yes") {
        $debug_openssl_path = File::Spec->rel2abs($debug_openssl_path);
        $varvals{"DEBUGDLLPATH"} =
            File::Spec->catfile($debug_openssl_path, "bin\\libeay32.dll");
        my $debug_openssl_inc =
            File::Spec->catfile($debug_openssl_path, "include");
        if (!-f File::Spec->catfile($debug_openssl_inc, "openssl\\ssl.h")) {
            die "can't find debug OpenSSL headers\n";
        }
        $varvals{"DEBUGINCPATH"} = $debug_openssl_inc;
        my $debug_openssl_lib =
            File::Spec->catfile($debug_openssl_path, "lib");
        if (!-f File::Spec->catfile($debug_openssl_lib, "libeay32.lib")) {
            die "can't find debug OpenSSL library\n";
        }
        $varvals{"DEBUGLIBPATH"} = $debug_openssl_lib;

    } else {
        $varvals{"DEBUGDLLPATH"} = $varvals{"DLLPATH"};
        $varvals{"DEBUGINCPATH"} = $varvals{"INCLUDEPATH"};
        $varvals{"DEBUGLIBPATH"} = $varvals{"LIBPATH"};
    }

    # OpenSSL support
    if ($verbose) {
        print "checking OpenSSL\n";
    }
    my $system_libs = "";
    if (-f $openssl_dll) {
        `copy "$openssl_dll" .`;
    } else {
        $system_libs = " user32.lib advapi32.lib gdi32.lib crypt32.lib";
    }
    my $inc = $openssl_inc;
    my $lib = File::Spec->catfile($openssl_lib, "libeay32.lib");
    open F, ">testossl.c" || die $!;
    print F << 'EOF';
#include <openssl/err.h>
int main() {
 ERR_clear_error();
 return 0;
}
EOF
    close F;
    my $compret = `cl /nologo /MD /I "$inc" testossl.c "$lib"$system_libs`;
    if (grep { -f and -x } ".\\testossl.exe") {
        `.\\testossl.exe`;
        if ($? != 0) {
            die "OpenSSL test failed\n";
        }
    } else {
        die "can't compile OpenSSL test: $compret\n";
    }

    # OpenSSL version
    if ($verbose) {
        print "checking OpenSSL version\n";
    }
    open F, ">testosslv.c" || die $!;
    print F << 'EOF';
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
int main() {
#ifndef OPENSSL_VERSION_NUMBER
 return -1;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x010000000L
 return 0;
#else
 return 1;
#endif
}
EOF
    close F;
    $compret = `cl /nologo /MD /I "$inc" testosslv.c "$lib"$system_libs`;
    if (grep { -f and -x } ".\\testosslv.exe") {
        `.\\testosslv.exe`;
        if ($? != 0) {
            die "OpenSLL version too old (1.0.0 or later required)\n";
        }
    } else {
        die "can't compile OpenSSL version test: $compret\n";
    }

    # OpenSSL ECC support
    if ($enable_ecc eq "yes") {
        if ($verbose) {
            print "checking OpenSSL ECC support\n";
        }
        open F, ">testecc.c" || die $!;
        print F << 'EOF';
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
int main() {
 EC_KEY *ec256, *ec384;
 ec256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
 ec384 = EC_KEY_new_by_curve_name(NID_secp384r1);
 if (ec256 == NULL || ec384 == NULL)
  return 1;
 return 0;
}
EOF
        close F;
        $compret = `cl /nologo /MD /I "$inc" testecc.c "$lib"$system_libs`;
        if (grep { -f and -x } ".\\testecc.exe") {
            `.\\testecc.exe`;
            if ($? != 0) {
                die "can't find P256 or P384: no ECC support\n";
            }
        } else {
            die "can't compile ECC test: $compret\n";
        }
    }

    # OpenSSL GOST support
    if ($enable_gost eq "yes") {
        if ($verbose) {
            print "checking OpenSSL GOST support\n";
        }
        open F, ">testgost.c" || die $!;
        print F << 'EOF';
#include <openssl/conf.h>
#include <openssl/engine.h>
int main() {
 ENGINE *e;
 EC_KEY *ek;
 ek = NULL;
 OPENSSL_config(NULL);
 e = ENGINE_by_id("gost");
 if (e == NULL)
  return 1;
 if (ENGINE_init(e) <= 0)
  return 1;
 return 0;
}
EOF
        close F;
        $compret = `cl /nologo /MD /I "$inc" testgost.c "$lib"$system_libs`;
        if (grep { -f and -x } ".\\testgost.exe") {
            `.\\testgost.exe`;
            if ($? != 0) {
                die "can't find GOST: no GOST support\n";
            }
        } else {
            die "can't compile GOST test: $compret\n";
        }
    }

    # OpenSSL EVP interface for AES key wrapping (aka RFC 3394)
    if ($verbose) {
        print "checking OpenSSL EVP interface for AES key wrapping\n";
    }
    open F, ">testrfc3394.c" || die $!;
    print F << 'EOF';
#include <openssl/evp.h>
int main() {
 EVP_aes_128_wrap();
 return 1;
}
EOF
    close F;
    `cl /nologo /MD /I "$inc" testrfc3394.c "$lib"$system_libs`;
    if (grep { -f and -x } ".\\testrfc3394.exe") {
        if ($verbose) {
            print "RFC 3394 is supported\n";
        }
        $condvals{"RFC3394"} = 1;
    } else {
        if ($verbose) {
            print "can't compile OpenSSL RFC 3394\n";
        }
    }

    # OpenSSL EVP interface for AES key wrap with pad (aka RFC 5649)
    if ($verbose) {
        print "checking OpenSSL EVP interface for AES key wrapping with pad\n";
    }
    open F, ">testrfc5649.c" || die $!;
    print F << 'EOF';
#include <openssl/evp.h>
int main() {
 EVP_aes_128_wrap_pad();
 return 1;
}
EOF
    close F;
    `cl /nologo /MD /I "$inc" testrfc5649.c "$lib"$system_libs`;
    if (grep { -f and -x } ".\\testrfc5649.exe") {
        if ($verbose) {
            print "RFC 5649 is supported\n";
        }
        $condvals{"RFC5649"} = 1;
    } else {
        if ($verbose) {
            print "can't compile OpenSSL RFC 5649\n";
        }
    }
}

# configure CppUnit

if ($want_tests eq "yes") {
    $condvals{"TESTS"} = 1;
    $cppunit_path = File::Spec->rel2abs($cppunit_path);
    my $cppunit_inc = File::Spec->catfile($cppunit_path, "include");
    if (!-f File::Spec->catfile($cppunit_inc, "cppunit\\Test.h"))  {
        die "can't find CppUnit headers\n";
    }
    $varvals{"CUINCPATH"} = $cppunit_inc;
    my $cppunit_lib = File::Spec->catfile($cppunit_path, "lib");
    if (!-f File::Spec->catfile($cppunit_lib, "cppunit.lib")) {
        $cppunit_lib = $cppunit_path;
    }
    if (!-f File::Spec->catfile($cppunit_lib, "cppunit.lib")) {
        die "can't find CppUnit library\n";
    }
    if ($enable_debug eq "yes") {
        if (!-f File::Spec->catfile($cppunit_lib, "cppunitd.lib")) {
            die "can't find debug CppUnit library\n";
        }
    }
    $varvals{"CULIBPATH"} = $cppunit_lib;
}

# misc

if ($enable_non_paged eq "yes") {
    $condvals{"NONPAGE"} = 1;
}

# escape spaces

sub kw {
    if ($_[0] =~ / /) {
        return "\"$_[0]\"";
    } else {
        return "$_[0]";
    }
}

# setup files with condition stacks and variable expansions

sub setupfile {
    my $line;
    my @Linesin;
    my @Linesout;
    my $filename = $_[0];
    my $cond;
    my @conds;
    my $pass = 1;
    my @passes;
    my $val;

    open F, $filename . ".in" || die $!;
    @Linesin = <F>;
    close F;

    foreach $line (@Linesin) {
        chomp $line;
        if ($line =~ /^\@IF (.*)$/) {
            if (defined($cond)) {
                unshift(@conds, $cond);
                unshift(@passes, $pass);
            }
            $cond = $1;
            if (defined($condvals{$cond})) {
                # do nothing
            } else {
                $pass = 0;
            }
            next;
        } elsif ($line =~ /^\@ELSE (.*)$/) {
            if ($cond ne $1) {
                die "\@ELSE $1 mismatch in $filename\n";
            }
            if (defined($condvals{$cond})) {
                $pass = 0;
            } else {
                if (scalar(@conds) > 0) {
                    $pass = $passes[0];
                } else {
                    $pass = 1;
                }
            }
            next;
        } elsif ($line =~ /^\@END (.*)$/) {
            if ($cond ne $1) {
                die "\@END $1 mismatch in $filename\n";
            }
            $cond = shift(@conds);
            if (scalar(@passes) > 0) {
                $pass = shift(@passes);
            } else {
                $pass = 1;
            }
            next;
        }
        if ($pass == 0) {
            next;
        }
        while ($line =~ /@([^@ ]*)@/) {
            if ($1 ~~ @varnames) {
                if (defined($varvals{$1})) {
                    $val = kw($varvals{$1});
                    $line = "$`$val$'";
                } else {
                    $line = "$`$'";
                }
            } else {
                die "unknown control $& in $filename\n";
            }
        }
        push @Linesout, $line;
    }

    open F, ">" . $filename || die $!;
    if ($verbose) {
        print "Setting up $filename\n";
    }
    foreach $line (@Linesout) {
        print F $line . "\n";
    }
    close F;
}

# status

if ($verbose) {
    my $name;

    print "Configuration Status\n";

    print "\tconditions:\n";
    foreach $name (@condnames) {
        if (defined($condvals{$name})) {
            print "\t\t$name is true\n";
        } else {
            print "\t\t$name is false\n";
        }
    }

    print "\tsubstitutions:\n";
    foreach $name (@varnames) {
        if (defined($varvals{$name})) {
            print qq(\t\t$name -> "$varvals{$name}"\n);
        }
    }

    print "\n";
}

# run

my $file;

foreach $file (@filelist) {
    setupfile($file);
}

# clean test files

if ($enable_keep ne "yes") {
    cleantest();
}

print "Configured.\n";

exit 0;

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
