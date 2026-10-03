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


if [[ "$CI" == "true" ]] && [[ "$CI_TEST_ENABLED" != "true" ]] ; then
	echo "This test is intended to be run with OpenSSL >= 3.5, skipping." >&2
	exit 77
fi

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

if is_botan_module ; then
	echo "This test is not compatible with the Botan2-based SoftHSM2, skipping." >&2
	exit 77
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

# ---------- token configuration ----------

setup_tokendir

# ---------- execution ----------

set -e

TOKEN_PIN=4321
TOKEN_ID=01
KEY_FILE="$TOKEN_DIR"/openssl_test_key
IMPORT_OUT="$TOKEN_DIR"/import.out
INIT_OUT="$TOKEN_DIR"/init.out

if ! softhsm2_tool --init-token --label test0 --slot free --so-pin 12345678 --pin $TOKEN_PIN >"$INIT_OUT" 2>&1; then
	fail "Failed to init token" "$INIT_OUT"
fi

openssl genpkey -algorithm "$OPENSSL_ALGO" -out "$KEY_FILE"

if ! softhsm2_tool --import "$KEY_FILE" --import-type keypair --id $TOKEN_ID --label test_key --token test0 --pin $TOKEN_PIN >"$IMPORT_OUT" 2>&1; then
	fail "Failed to import $ALGO_NAME key" "$IMPORT_OUT"
fi

if ! grep -q "The $ALGO_NAME key pair with label=test_key has been imported." "$IMPORT_OUT"; then
	fail "ERROR: Expected $ALGO_NAME import success message" "$IMPORT_OUT"
fi

clean_tokendir
