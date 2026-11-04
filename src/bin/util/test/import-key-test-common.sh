#! /bin/bash
# 
# Copyright (c) 2026 SoftHSMv2 contributors
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Common logic for PQC key-pair import tests.
#
# Required variables (set by the caller before sourcing this file):
#   CI_TEST_ENABLED  – value of the algorithm-specific CI gate (e.g. $MLDSA_TEST)
#   ALGO_NAME        – human-readable algorithm name, e.g. "ML-DSA"
#   OPENSSL_ALGO     – OpenSSL algorithm identifier, e.g. "ML-DSA-44"
#   TOKEN_DIR_NAME   – token directory name, e.g. "tokens-mldsa-44"
# Optional: KEY_FILE_SOURCE – PKCS#8 PEM fixture when OpenSSL cannot generate the key.


if [[ "$CI" == "true" ]] && [[ "$CI_TEST_ENABLED" != "true" ]] ; then
	echo "This test is intended to be run with OpenSSL >= 3.5, skipping." >&2
	exit 77
fi

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
	# Autotools uses .libs; CMake places the module directly in lib.
	if ! D=$(cd ../../../lib/.libs/ 2>/dev/null && pwd) ; then
		if ! D=$(cd ../../../lib/ 2>/dev/null && pwd) ; then
			D=
		fi
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
	echo "error: unexpected module suffix" >&2
	exit 1
fi
if command -v realpath > /dev/null ; then
	P11MODULE=$(realpath "$P11MODULE")
fi

IS_BOTAN=$(strings "$P11MODULE" | grep botan | wc -l)
if [[ "$IS_BOTAN" -gt 0 ]] ; then
	echo "This test is not compatible with the Botan2-based SoftHSM2, skipping." >&2
	exit 77
fi

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

case $openssl_version in
*"OpenSSL 0.9."*|\
*"OpenSSL 1."*|\
*"OpenSSL 3.0."*|\
*"OpenSSL 3.1."*|\
*"OpenSSL 3.2."*|\
*"OpenSSL 3.3."*|\
*"OpenSSL 3.4."*)
	echo "$openssl_version does not support $ALGO_NAME (requires >= 3.5)" >&2
	exit 77
	;;
esac
# NOTE OpenSSL > 3.5

# ---------- helper functions ----------

softhsm2_tool() {
	if test "$RUNNER_OS" = "Windows" ; then
		"$CWD"/../"${CONFIG:-Debug}"/softhsm2-util.exe --module "$P11MODULE" ${1+"$@"}
	else
		"$CWD"/../softhsm2-util --module "$P11MODULE" ${1+"$@"}
	fi
}

clean_tokendir() {
	rm -rf "$TOKEN_DIR"
}

# ---------- token configuration ----------

TOKEN_DIR="$CWD"/"$TOKEN_DIR_NAME"
clean_tokendir
export SOFTHSM2_CONF="$TOKEN_DIR"/softhsm2.conf

mkdir -p "$TOKEN_DIR"

if test "$RUNNER_OS" = "Windows" ; then
	WINDOWS_TOKEN_DIR=$(realpath "$TOKEN_DIR")
	WINDOWS_TOKEN_DIR=$(cygpath -w "$WINDOWS_TOKEN_DIR")
	cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WINDOWS_TOKEN_DIR
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
log.level = DEBUG
log.file = $WINDOWS_TOKEN_DIR\token.log
EOF
else
	cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
log.level = DEBUG
log.file = $TOKEN_DIR/token.log
EOF
fi

SOFTHSM2_CONF=$(realpath "$SOFTHSM2_CONF")

# ---------- execution ----------

set -e

TOKEN_PIN=4321
TOKEN_ID=01
KEY_FILE="$TOKEN_DIR"/openssl_test_key
IMPORT_OUT="$TOKEN_DIR"/import.out
INIT_OUT="$TOKEN_DIR"/init.out

if ! softhsm2_tool --init-token --label test0 --slot free --so-pin 12345678 --pin $TOKEN_PIN >"$INIT_OUT" 2>&1; then
	echo "Failed to init token"
	cat "$INIT_OUT"
	cat "$TOKEN_DIR/token.log"
	clean_tokendir
	exit 1
fi

if test -n "${KEY_FILE_SOURCE:-}" ; then
	cp "$KEY_FILE_SOURCE" "$KEY_FILE"
else
	openssl genpkey -algorithm "$OPENSSL_ALGO" -out "$KEY_FILE"
fi

if ! softhsm2_tool --import "$KEY_FILE" --import-type keypair --id $TOKEN_ID --label test_key --token test0 --pin $TOKEN_PIN >"$IMPORT_OUT" 2>&1; then
	echo "Failed to import $ALGO_NAME key"
	cat "$IMPORT_OUT"
	cat "$TOKEN_DIR/token.log"
	clean_tokendir
	exit 1
fi

if ! grep -q "The $ALGO_NAME key pair with label=test_key has been imported." "$IMPORT_OUT"; then
	echo "ERROR: Expected $ALGO_NAME import success message"
	cat "$IMPORT_OUT"
	cat "$TOKEN_DIR/token.log"
	clean_tokendir
	exit 1
fi

clean_tokendir
