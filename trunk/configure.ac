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
AC_INIT([softHSM],[SOFTHSM_VERSION_MAJOR.SOFTHSM_VERSION_MINOR.SOFTHSM_VERSION_FIX[]PACKAGE_SUFFIX])
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


# Use OpenSSL or Botan


# Check for libraries
# Check for headers


# Define some variables for the code
# AC_DEFINE_UNQUOTED(
# 	[VERSION_MAJOR],
# 	[SOFTHSM_VERSION_MAJOR],
# 	[SoftHSM major version number via PKCS#11]
# )
# AC_DEFINE_UNQUOTED(
# 	[VERSION_MINOR],
# 	[SOFTHSM_VERSION_MINOR],
# 	[SoftHSM minor version number via PKCS#11]
# )



# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/lib/Makefile
])

AC_OUTPUT
