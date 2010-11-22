dnl
dnl $Id$
dnl

##################
#                #
#    Version     #
#                #
################

# Program version

define([SOFTHSM_VERSION_MAJOR], [2])
define([SOFTHSM_VERSION_MINOR], [0])
define([SOFTHSM_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [a1])

# Library version

# Code changed:                      SOFTHSM_VERSION_REVISION++
# Interface added/removed/changed:   SOFTHSM_VERSION_CURRENT++, SOFTHSM_VERSION_REVISION=0
# Interface added:                   SOFTHSM_VERSION_AGE++
# Interface removed:                 SOFTHSM_VERSION_AGE=0

define([SOFTHSM_VERSION_CURRENT], [2])
define([SOFTHSM_VERSION_AGE], [1])
define([SOFTHSM_VERSION_REVISION], [0])

##################
#                #
# Configure code #
#                #
##################

# Init
AC_PREREQ(2.61)
AC_INIT([SoftHSM],[SOFTHSM_VERSION_MAJOR.SOFTHSM_VERSION_MINOR.SOFTHSM_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

# Version info for the library
VERSION_INFO="SOFTHSM_VERSION_CURRENT:SOFTHSM_VERSION_REVISION:SOFTHSM_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for compilers
AC_PROG_CC
AC_PROG_CXX

# Compiler flags
ACX_PEDANTIC
ACX_STRICT

# What crypto backend to use and if we want to have support GOST
ACX_CRYPTO_BACKEND

# Non-paged memory for secure storage
ACX_NON_PAGED_MEMORY

# Log level
AC_ARG_WITH(
	[loglevel],
	[AS_HELP_STRING([--with-loglevel=INT],[The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)])],
	[SOFTLOGLEVEL="$withval"],
	[SOFTLOGLEVEL=3]
)

# If the user want to have the migration tool
# Requires SQLite3
AC_ARG_WITH(migrate,
	AC_HELP_STRING([--with-migrate],
		[Build the migration tool. Requires SQLite3.]
	),
	[build_migrate="${withval}"],
	[build_migrate="no"]
)
AC_MSG_CHECKING(if building with softhsm-migrate)
if test "x${build_migrate}" = "xyes"; then
	AC_MSG_RESULT(yes)
	ACX_SQLITE3
	ACX_YIELD
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_MIGRATE], [test "x${build_migrate}" = "xyes"])

# Check for libraries
ACX_DLOPEN
ACX_SEMAPHORE

# Check for headers
AC_CHECK_HEADERS([pthread.h])

# Set full directory paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
default_softhsm2_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/softhsm2.conf"
softhsmtokendir=${full_localstatedir}/softhsm/tokens/

# Define some variables for the code
AC_DEFINE_UNQUOTED(
	[VERSION_MAJOR],
	[SOFTHSM_VERSION_MAJOR],
	[SoftHSM major version number via PKCS#11]
)
AC_DEFINE_UNQUOTED(
	[VERSION_MINOR],
	[SOFTHSM_VERSION_MINOR],
	[SoftHSM minor version number via PKCS#11]
)
AC_DEFINE_UNQUOTED(
	[SOFTLOGLEVEL],
	[$SOFTLOGLEVEL],
	[The log level set by the user]
)
AC_DEFINE_UNQUOTED(
	[MAX_PIN_LEN],
	[255],
	[Maximum PIN length]
)
AC_DEFINE_UNQUOTED(
	[MIN_PIN_LEN],
	[4],
	[Minimum PIN length]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_SOFTHSM2_CONF],
	["$default_softhsm2_conf"],
	[The default location of softhsm2.conf]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_TOKENDIR],
	["$softhsmtokendir"],
	[The default location of the token directory]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_PKCS11_LIB],
	["$full_libdir/libsofthsm.so"],
	[The default PKCS#11 library]
)

AC_SUBST([softhsmtokendir])

# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/lib/Makefile
	src/lib/common/Makefile
	src/lib/common/softhsm2.conf
	src/lib/crypto/Makefile
	src/lib/crypto/test/Makefile
	src/lib/data_mgr/Makefile
	src/lib/data_mgr/test/Makefile
	src/lib/object_store/Makefile
	src/lib/object_store/test/Makefile
	src/lib/session_mgr/Makefile
	src/lib/session_mgr/test/Makefile
	src/lib/slot_mgr/Makefile
	src/lib/slot_mgr/test/Makefile
	src/lib/test/Makefile
	src/lib/test/softhsm2.conf
	src/lib/user_mgr/Makefile
	src/bin/Makefile
	src/bin/common/Makefile
	src/bin/keyconv/Makefile
	src/bin/migrate/Makefile
	src/bin/util/Makefile
])

AC_OUTPUT
