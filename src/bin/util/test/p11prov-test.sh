#! /bin/bash
# 
# Copyright (c) 2026 SoftHSMv2 contributors
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Regression test for the process-exit crash reported in issues #729 and
# #780: an OpenSSL application using the pkcs11-provider closes its cached
# PKCS#11 sessions and finalises the module from an atexit handler, after
# the C++ runtime has started destroying static objects. SoftHSM2 must stay
# usable until C_Finalize is called, so the openssl process must exit
# cleanly.
#
# Requires OpenSSL 3 and the pkcs11-provider module. The provider is
# looked up in the OpenSSL MODULESDIR; set PKCS11_PROVIDER_MODULE to
# override the location. The test is skipped when either is missing.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-common.sh"

case $openssl_version in
*"OpenSSL 0.9."*|\
*"OpenSSL 1."*)
	echo "$openssl_version has no provider support, skipping." >&2
	exit 77
	;;
*"OpenSSL "*)
	;;
*)
	echo "unsupported: $openssl_version, skipping." >&2
	exit 77
	;;
esac

# ---------- locate the PKCS#11 provider ----------

if test -n "$PKCS11_PROVIDER_MODULE" ; then
	if ! test -f "$PKCS11_PROVIDER_MODULE" ; then
		echo "error: PKCS11_PROVIDER_MODULE=$PKCS11_PROVIDER_MODULE does not exist" >&2
		exit 1
	fi
else
	MODULESDIR=$(openssl version -m | sed -n 's/^MODULESDIR: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p')
	if test -z "$MODULESDIR" ; then
		echo "cannot determine OpenSSL MODULESDIR, skipping." >&2
		exit 77
	fi
	for N in pkcs11 libpkcs11 ; do
		for S in so dll ; do
			test -f "$MODULESDIR/$N.$S" || continue
			PKCS11_PROVIDER_MODULE="$MODULESDIR/$N.$S"
			break
		done
		test -n "$PKCS11_PROVIDER_MODULE" && break
	done
	if test -z "$PKCS11_PROVIDER_MODULE" ; then
		echo "pkcs11-provider not found in $MODULESDIR, skipping." >&2
		exit 77
	fi
fi

# ---------- token and OpenSSL configuration ----------

TOKEN_DIR_NAME="tokens-p11prov"
setup_tokendir

OPENSSL_CONF="$TOKEN_DIR"/openssl.cnf
cat > "$OPENSSL_CONF" <<EOC
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = $(native_path "$PKCS11_PROVIDER_MODULE")
pkcs11-module-path = $(native_path "$P11MODULE")
activate = 1
EOC
export OPENSSL_CONF

# ---------- execution ----------

set -e

TOKEN_PIN=4321
TOKEN_ID=01
KEY_URI="pkcs11:id=%$TOKEN_ID;type=private"
KEY_FILE="$TOKEN_DIR"/openssl_test_key
DATA_FILE="$TOKEN_DIR"/data
SIG_FILE="$TOKEN_DIR"/data.sig
INIT_OUT="$TOKEN_DIR"/init.out
IMPORT_OUT="$TOKEN_DIR"/import.out
SIGN_OUT="$TOKEN_DIR"/sign.out
VERIFY_OUT="$TOKEN_DIR"/verify.out

if ! softhsm2_tool --init-token --label test0 --slot free --so-pin 12345678 --pin $TOKEN_PIN >"$INIT_OUT" 2>&1; then
	fail "Failed to init token" "$INIT_OUT"
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_FILE" 2>/dev/null

if ! softhsm2_tool --import "$KEY_FILE" --import-type keypair --id $TOKEN_ID --label test_key --token test0 --pin $TOKEN_PIN >"$IMPORT_OUT" 2>&1; then
	fail "Failed to import RSA key" "$IMPORT_OUT"
fi

echo "SoftHSM2 pkcs11-provider exit test" > "$DATA_FILE"

# Sign through the provider. The process must exit cleanly: before the fix
# for #729/#780 it produced the signature and then crashed with SIGSEGV in
# C_CloseSession during OpenSSL's atexit cleanup.
openssl pkeyutl -sign -inkey "$KEY_URI" -passin pass:$TOKEN_PIN -rawin -in "$DATA_FILE" -out "$SIG_FILE" >"$SIGN_OUT" 2>&1 \
	|| fail "openssl pkeyutl -sign via pkcs11-provider failed with exit status $?" "$SIGN_OUT"

# Verify with the software copy of the key to make sure the signature
# really came from the imported key.
if ! openssl pkeyutl -verify -inkey "$KEY_FILE" -rawin -in "$DATA_FILE" -sigfile "$SIG_FILE" >"$VERIFY_OUT" 2>&1; then
	fail "Signature verification failed" "$VERIFY_OUT"
fi

clean_tokendir
