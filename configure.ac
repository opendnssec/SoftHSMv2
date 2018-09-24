##################
#                #
#    Version     #
#                #
##################

# Program version

define([SOFTHSM_VERSION_MAJOR], [2])
define([SOFTHSM_VERSION_MINOR], [5])
define([SOFTHSM_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [])

# Library version

# Code changed:                      SOFTHSM_VERSION_REVISION++
# Interface added/removed/changed:   SOFTHSM_VERSION_CURRENT++, SOFTHSM_VERSION_REVISION=0
# Interface added:                   SOFTHSM_VERSION_AGE++
# Interface removed:                 SOFTHSM_VERSION_AGE=0

define([SOFTHSM_VERSION_CURRENT], [2])
define([SOFTHSM_VERSION_AGE], [1])
define([SOFTHSM_VERSION_REVISION], [5])

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
AM_INIT_AUTOMAKE([foreign subdir-objects])
ACX_PREFIXHACK

# Version info for the library
VERSION_INFO="SOFTHSM_VERSION_CURRENT:SOFTHSM_VERSION_REVISION:SOFTHSM_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for compilers
AC_PROG_CC
AC_PROG_CXX
PKG_PROG_PKG_CONFIG

# Compiler flags
ACX_PEDANTIC
ACX_STRICT
ACX_64BIT
AX_CXX_COMPILE_STDCXX_11([noext],[optional])

# Check for libraries (-ldl can be required by OpenSSL too)
ACX_DLOPEN

# Check for headers
AC_CHECK_HEADERS([pthread.h])

# What crypto backend to use and if we want to have support GOST
ACX_CRYPTO_BACKEND

# Non-paged memory for secure storage
ACX_NON_PAGED_MEMORY

# If the user want to have the migration tool
# Requires SQLite3
AC_ARG_WITH(migrate,
	AC_HELP_STRING([--with-migrate],
		[Build the migration tool. Requires SQLite3.]
	),
	[build_migrate="${withval}"],
	[build_migrate="no"]
)
AC_MSG_CHECKING(if building with softhsm2-migrate)
if test "x${build_migrate}" = "xyes"; then
	AC_MSG_RESULT(yes)
	ACX_YIELD
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_MIGRATE], [test "x${build_migrate}" = "xyes"])

# If the user wants to have the database storage backend
AC_ARG_WITH([objectstore-backend-db],
	AC_HELP_STRING([--with-objectstore-backend-db],
		[Build with object store backend database (SQLite3).]
	),
	[build_objectstore_backend_db="${withval}"],
	[build_objectstore_backend_db="no"]
)
AC_MSG_CHECKING(if building database object store backend)
if test "x${build_objectstore_backend_db}" = "xyes"; then
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED(
		[HAVE_OBJECTSTORE_BACKEND_DB],
		[1],
		[Build with object store database backend.]
	)
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_OBJECTSTORE_BACKEND_DB], [test "x${build_objectstore_backend_db}" = "xyes"])

# Require SQLite3 if either building --with-migrate or --with-objectstore-backend-db
AC_MSG_CHECKING(if SQLite3 required)
if test "x${build_migrate}" = "xyes" -o "x${build_objectstore_backend_db}" = "xyes"; then
	AC_MSG_RESULT(yes)
	ACX_SQLITE3
else
	AC_MSG_RESULT(no)
fi

# Set visibility flags so only PKCS#11 entry points are exported
ACX_VISIBILITY

# If we should install the p11-kit module
ACX_P11KIT

# cppunit settings
ACX_CPPUNIT

# Set full directory paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
default_softhsm2_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/softhsm2.conf"
softhsmtokendir=${full_localstatedir}/lib/softhsm/tokens/

# Install the library in a sub-directory
full_libdir="$full_libdir/softhsm"
libdir=$full_libdir
default_softhsm2_lib="$full_libdir/libsofthsm2.so"

# For getConfigPath()
AC_CHECK_FUNCS([getpwuid_r])

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
	[DEFAULT_OBJECTSTORE_BACKEND],
	["file"],
	[Default storage backend for token objects]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_LOG_LEVEL],
	["INFO"],
	[The default log level]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_PKCS11_LIB],
	["$default_softhsm2_lib"],
	[The default PKCS#11 library]
)

AC_SUBST([softhsmtokendir])
AC_SUBST([default_softhsm2_conf])
AC_SUBST([default_softhsm2_lib])

# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	softhsm2.module
	src/Makefile
	src/lib/Makefile
	src/lib/common/Makefile
	src/lib/common/softhsm2.conf
	src/lib/common/softhsm2.conf.5
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
	src/lib/handle_mgr/Makefile
	src/lib/handle_mgr/test/Makefile
	src/lib/test/Makefile
	src/lib/test/softhsm2.conf
	src/lib/test/softhsm2-alt.conf
	src/lib/test/tokens/dummy
	src/bin/Makefile
	src/bin/common/Makefile
	src/bin/dump/Makefile
	src/bin/keyconv/Makefile
	src/bin/migrate/Makefile
	src/bin/util/Makefile
])

AC_OUTPUT
