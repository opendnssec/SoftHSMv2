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

# variables to expand

my %varvals;

my @varnames = ("CUINCPATH",
                "CULIBPATH",
                "DEBUGDLLPATH",
                "DEBUGINCPATH",
                "DEBUGLIBPATH",
                "DLLPATH",
                "INCLUDEPATH",
                "LIBNAME",
                "LIBPATH",
		"LOGLEVEL",
                "PLATFORM",
                "PLATFORMDIR");

# conditions to stack

my %condvals;

my @condnames = ("BOTAN",
                 "ECC",
                 "GOST",
                 "OPENSSL",
                 "TESTS");

# enable-xxx/disable-xxx arguments

my @enablelist = ("debug",
                  "ecc",
                  "gost");

# with-xxx/without-xxx arguments

my @withlist = ("botan",
                "cppunit",
                "crypto-backend",
                "loglevel",
                "openssl",
                "platform");

# general arguments

my @optionlist = ("help", "verbose", "clean");

# usage

my @usage = ("Usage: perl Configure.pl help\n",
             "       perl Configure.pl options*\n",
             "       perl Configure.pl clean\n");

# help

my @help = (
"'perl Configure.pl' configures SoftHSMv2 build files.\n\n",
@usage,
"\nGeneral Options and Commands:\n",
"  verbose             (options) print messages\n",
"  help                (command) print this help\n",
"  clean               (command) clean up generated files\n",
"  <none>              (command) print a summary of the configuration\n",
"\nOptional Features:\n",
"  enable-debug        enable build of Debug config [default=yes]\n",
"  enable-ecc          enable support for ECC [default=yes]\n",
"  enable-gost         enable support for GOST [default=yes]\n",
"\nRequired Packages:\n",
"  with-platform       select the platform [win32|x64]\n",
"  with-crypto-backend select the crypto backend [botan|openssl]\n",
"\nOptional Packages:\n",
"  with-botan=PATH     speficy prefix of path of Botan\n",
"  with-openssl=PATH   speficy prefix of path of OpenSSL\n",
"  with-cppunit=PATH   specify prefix of path of CppUnit\n",
"  with-loglevel=INT   the log level [0..4] [default=3]\n");

# variables for parsing

my $configargs;
my $verbose = 0;
my $want_help = "no";
my $want_clean = "no";
my $want_unknown = "no";
my $unknown_value;
my $enable_debug = "yes";
my $enable_ecc = "yes";
my $enable_gost = "yes";
my $platform = "none";
my $crypto_backend = "none";
my $botan_path = "..\\..\\btn";
my $debug_botan_path = "..\\..\\btn_d";
my $openssl_path = "..\\..\\ssl";
my $debug_openssl_path = "..\\..\\ssl_d";
my $want_tests = "yes";
my $cppunit_path = "..\\..\\cu";
my $loglevel = 3;

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

    if ($key =~ /^debug$/i) {
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

    if ($key =~ /^platform$/i) {
        if ($val =~ /^win32$/i) {
            $platform = "win32";
        } elsif ($val =~ /^x64$/i) {
            $platform = "x64";
        } else {
            $want_unknown = "yes";
            $unknown_value = "with-platform=" . $val;
        }
    } elsif ($key =~ /^crypto-backend$/i) {
        if ($val =~ /^botan$/i) {
            $crypto_backend = "botan";
        } elsif($val =~ /^openssl$/i) {
            $crypto_backend = "openssl";
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
    } elsif ($key =~ /^openssl$/i) {
        if ($val =~ /^no$/i) {
            $want_unknown = "yes";
            $unknown_value = "without-openssl doesn't make sense\n";
        } elsif ($val !~ /^yes$/i) {
            $openssl_path = $val;
        }
    } elsif ($key =~ /^cppunit$/i) {
        if ($val =~ /^no$/i) {
            $want_tests = "no";
        } elsif ($val !~ /^yes$/i) {
            $cppunit_path = $val;
        }
    } elsif ($key =~ /^loglevel$/i) {
        if ($val =~ /^no$/i) {
            $want_unknown = "yes";
            $unknown_value = "without-loglevel doesn't make sense\n";
        } elsif ($val !~ /^yes$/i) {
            if ($val eq "0") {
                $loglevel = 0;
            } elsif ($val eq "1") {
                $loglevel = 1;
            } elsif ($val eq "2") {
                $loglevel = 2;
            } elsif ($val eq "3") {
                $loglevel = 3;
            } elsif ($val eq "4") {
                $loglevel = 4;
            } else {
                $want_unknown = "yes";
                $unknown_value = "with-loglevel=" . $val;
            }
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

if ($want_clean eq "yes") {
    my $file;
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

# required

if ($platform eq "none") {
    print STDERR "with-platform=[win32|x64] is REQUIRED\n";
    exit 1;
}
if ($crypto_backend eq "none") {
    print STDERR "with-crypto-backend=[botan|openssl] is REQUIRED\n";
    exit 1;
}

# debug

if ($enable_debug eq "yes") {
    $debug_botan_path = $botan_path . "_d";
    $debug_openssl_path = $openssl_path . "_d";
}

# verbose

if ($verbose) {
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
    print "platform: $platform\n";
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
    print "loglevel: $loglevel\n";
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
    $varvals{"DLLPATH"} = File::Spec->catfile($botan_path, "botan.dll");
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
        $debug_botan_path = $botan_path;
        $varvals{"DEBUGDLLPATH"} = $varvals{"DLLPATH"};
        $varvals{"DEBUGINCPATH"} = $varvals{"INCLUDEPATH"};
        $varvals{"DEBUGLIBPATH"} = $varvals{"LIBPATH"};
    }
} else {
    $condvals{"OPENSSL"} = 1;
    $varvals{"LIBNAME"} = "libeay32.lib";
    $openssl_path = File::Spec->rel2abs($openssl_path);
    $varvals{"DLLPATH"} =
        File::Spec->catfile($openssl_path, "bin\\libeay32.dll");
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
        $debug_openssl_path = $openssl_path;
        $varvals{"DEBUGDLLPATH"} = $varvals{"DLLPATH"};
        $varvals{"DEBUGINCPATH"} = $varvals{"INCLUDEPATH"};
        $varvals{"DEBUGLIBPATH"} = $varvals{"LIBPATH"};
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

# configure loglevel

$varvals{"LOGLEVEL"} = "$loglevel";

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

print "Configured.\n";

exit 0;
