#! /bin/bash
# 
# Copyright (c) 2026 SoftHSMv2 contributors
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Common setup for the softhsm2-util shell tests. Source this file from a
# test script. It locates the SoftHSM2 PKCS#11 module, the softhsm2-util
# binary and the openssl utility, and provides helpers to prepare a token
# directory.
#
# Provided variables:
#   P11MODULE        – absolute path to the SoftHSM2 PKCS#11 module
#   CWD              – directory the test is executed from
#   OPENSSL          – path to the openssl utility
#   openssl_version  – output of "openssl version"
#
# Provided functions:
#   openssl          – wrapper running $OPENSSL
#   softhsm2_tool    – runs softhsm2-util with --module $P11MODULE
#   is_botan_module  – succeeds when the module is built with Botan
#   setup_tokendir   – creates $TOKEN_DIR from $TOKEN_DIR_NAME and writes
#                      softhsm2.conf, exported as SOFTHSM2_CONF
#   clean_tokendir   – removes $TOKEN_DIR
#   fail             – prints a message and the token log, cleans up, exits 1


# ---------- locate the SoftHSM library ----------

if test "$RUNNER_OS" = "Windows" ; then
	if test -n "${CONFIG:-${CMAKE_BUILD_TYPE:-}}" ; then
		_PROBE_DIRS="${CONFIG:-$CMAKE_BUILD_TYPE}"
	else
		_PROBE_DIRS="Debug Release RelWithDebInfo MinSizeRel"
	fi
	D=
	for _CFG in $_PROBE_DIRS ; do
		if test -d "../../../lib/$_CFG/" ; then
			D=$(cd "../../../lib/$_CFG/" 2>/dev/null && pwd)
			test -n "$D" || continue
			CONFIG="$_CFG"
			break
		fi
	done
else
	if ! D=$(cd ../../../lib/.libs/ 2>/dev/null && pwd) ; then
		D=
	fi
fi

if test -z "$D" ; then
	echo "unexpectedly missing library directory" >&2
	exit 99
fi

P11MODULE=
for S in so dll ; do
	for F in "$D"/*softhsm2."$S" ; do
		test -f "$F" || continue
		P11MODULE="$F"
		break
	done
	test -n "$P11MODULE" && break
done
if test -z "$P11MODULE" ; then
	echo "error: SoftHSM2 module not found in $D" >&2
	exit 1
fi
if command -v realpath > /dev/null ; then
	P11MODULE=$(realpath "$P11MODULE")
fi

is_botan_module() {
	test "$(strings "$P11MODULE" | grep -c botan)" -gt 0
}

CWD=$(pwd)

# ---------- binaries ----------

OPENSSL=${OPENSSL-openssl}
OPENSSL=$(command -v "$OPENSSL")
if test -z "$OPENSSL" ; then
	echo "error: openssl utility not found" >&2
	exit 1
fi

openssl() {
	"$OPENSSL" ${1+"$@"}
}

openssl_version=$(openssl version) || exit $?
if test -z "$openssl_version" ; then
	echo "cannot determine OpenSSL version" >&2
	exit 1
fi

softhsm2_tool() {
	if test "$RUNNER_OS" = "Windows" ; then
		"$CWD"/../"${CONFIG:-Debug}"/softhsm2-util.exe --module "$P11MODULE" ${1+"$@"}
	else
		"$CWD"/../softhsm2-util --module "$P11MODULE" ${1+"$@"}
	fi
}

# ---------- token directory helpers ----------

clean_tokendir() {
	rm -rf "$TOKEN_DIR"
}

# Convert a path for use in configuration files read by native binaries.
native_path() {
	if test "$RUNNER_OS" = "Windows" ; then
		cygpath -w "$(realpath "$1")"
	else
		printf '%s\n' "$1"
	fi
}

# Requires TOKEN_DIR_NAME to be set by the caller.
setup_tokendir() {
	TOKEN_DIR="$CWD"/"$TOKEN_DIR_NAME"
	clean_tokendir
	mkdir -p "$TOKEN_DIR"

	export SOFTHSM2_CONF="$TOKEN_DIR"/softhsm2.conf
	TOKEN_LOG="$TOKEN_DIR"/token.log

	local native_tokendir native_tokenlog
	native_tokendir=$(native_path "$TOKEN_DIR")
	native_tokenlog=$(native_path "$TOKEN_LOG")
	cat > "$SOFTHSM2_CONF" <<EOC
directories.tokendir = $native_tokendir
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
log.level = DEBUG
log.file = $native_tokenlog
EOC

	SOFTHSM2_CONF=$(realpath "$SOFTHSM2_CONF")
}

# Usage: fail "message" [file-to-dump ...]
fail() {
	echo "$1" >&2
	shift
	for f in "$@" "$TOKEN_LOG" ; do
		test -f "$f" && cat "$f"
	done
	clean_tokendir
	exit 1
}
