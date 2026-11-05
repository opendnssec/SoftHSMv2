AC_DEFUN([ACX_CRYPTO_BACKEND],[

	# First check if we want to support ECC and GOST

	AC_ARG_ENABLE(ecc,
		AS_HELP_STRING([--enable-ecc],
			[Enable support for ECC (default detect)]
		),
		[enable_ecc="${enableval}"],
		[enable_ecc="detect"]
	)

	AC_ARG_ENABLE(gost,
		AS_HELP_STRING([--enable-gost],
			[Enable support for GOST (default detect)]
		),
		[enable_gost="${enableval}"],
		[enable_gost="detect"]
	)

	# Add Eddsa check

	AC_ARG_ENABLE(eddsa,
		AS_HELP_STRING([--enable-eddsa],
			[Enable support for EDDSA (default detect)]
		),
		[enable_eddsa="${enableval}"],
		[enable_eddsa="detect"]
	)

	# Add ML-DSA check

	AC_ARG_ENABLE(mldsa,
		AS_HELP_STRING([--enable-mldsa],
			[Enable support for ML-DSA (default detect)]
		),
		[enable_mldsa="${enableval}"],
		[enable_mldsa="detect"]
	)

	# Add ML-KEM check

	AC_ARG_ENABLE(mlkem,
		AS_HELP_STRING([--enable-mlkem],
			[Enable support for ML-KEM (default detect)]
		),
		[enable_mlkem="${enableval}"],
		[enable_mlkem="detect"]
	)

	# Add SHA3 check

	AC_ARG_ENABLE(sha3,
		AS_HELP_STRING([--enable-sha3],
			[Enable support for SHA3 (default detect)]
		),
		[enable_sha3="${enableval}"],
		[enable_sha3="detect"]
	)

	# Second check for the FIPS 140-2 mode

	AC_ARG_ENABLE(fips,
		AS_HELP_STRING([--enable-fips],
			[Enable support for FIPS 140-2 mode (default disabled)]
		),
		[enable_fips="${enableval}"],
		[enable_fips="no"]
	)
	AC_MSG_CHECKING(for FIPS 140-2 mode)
	if test "x${enable_fips}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_FIPS],
			[],
			[Compile with FIPS 140-2 mode]
		)
	else
		AC_MSG_RESULT(no)
	fi

	# Option to disable usage engines

	AC_ARG_ENABLE(openssl-engines,
		AS_HELP_STRING([--disable-openssl-engines],
			[Disable OpenSSL engines usage]
		),
		[enable_openssl_engines="${enableval}"],
		[enable_openssl_engines="yes"]
	)

	# Then check what crypto library we want to use

	AC_ARG_WITH(crypto-backend,
		AS_HELP_STRING([--with-crypto-backend],
			[Select crypto backend (openssl|botan)]
		),
		[crypto_backend="${withval}"],
		[crypto_backend="openssl"]
	)

	AC_MSG_CHECKING(for crypto backend)

	if test "x${crypto_backend}" = "xopenssl"; then
		AC_MSG_RESULT(OpenSSL)

		if test "x${enable_fips}" = "xyes"; then
			ACX_OPENSSL(1,0,1)
		else
			ACX_OPENSSL(1,0,0)
		fi

		CRYPTO_INCLUDES=$OPENSSL_INCLUDES
		CRYPTO_LIBS=$OPENSSL_LIBS

		case "${enable_ecc}" in
			yes|detect) ACX_OPENSSL_ECC;;
		esac
		case "${enable_ecc}-${have_lib_openssl_ecc_support}" in
			yes-no) AC_MSG_ERROR([OpenSSL library has no ECC support]);;
			detect-*) enable_ecc="${have_lib_openssl_ecc_support}";;
		esac

		case "${enable_eddsa}" in
			yes|detect) ACX_OPENSSL_EDDSA;;
		esac
		case "${enable_eddsa}-${have_lib_openssl_ed25519_support}-${have_lib_openssl_ed448_support}" in
			yes*-no*) AC_MSG_ERROR([OpenSSL library has no EDDSA support]);;
			detect-yes-yes) enable_eddsa="yes";;
			detect*-no*) enable_eddsa="no";;
		esac

		case "${enable_mldsa}" in
			yes|detect) ACX_OPENSSL_MLDSA;;
		esac
		case "${enable_mldsa}-${have_lib_openssl_mldsa_support}" in
			yes-no) AC_MSG_ERROR([OpenSSL library has no ML-DSA support]);;
			detect-yes) enable_mldsa="yes";;
			detect-no) enable_mldsa="no";;
		esac

		case "${enable_mlkem}" in
			yes|detect) ACX_OPENSSL_MLKEM;;
		esac
		case "${enable_mlkem}-${have_lib_openssl_mlkem_support}" in
			yes-no) AC_MSG_ERROR([OpenSSL library has no ML-KEM support]);;
			detect-yes) enable_mlkem="yes";;
			detect-no) enable_mlkem="no";;
		esac

		case "${enable_sha3}" in
			yes|detect) ACX_OPENSSL_SHA3;;
		esac
		case "${enable_sha3}-${have_lib_openssl_sha3_support}" in
			yes-no) AC_MSG_ERROR([OpenSSL library has no SHA3 support (requires OpenSSL >= 1.1.1 or LibreSSL >= 3.8.0)]);;
			detect-*) enable_sha3="${have_lib_openssl_sha3_support}";;
		esac

		case "${enable_gost}-${enable_fips}" in
			yes-yes) AC_MSG_ERROR([GOST is not FIPS approved]);;
			yes-no|detect-no) ACX_OPENSSL_GOST;;
		esac
		case "${enable_gost}-${have_lib_openssl_gost_support}" in
			yes-no) AC_MSG_ERROR([OpenSSL library has no GOST support]);;
			detect-*) enable_gost="${have_lib_openssl_gost_support}";;
		esac

		if test "x${enable_fips}" = "xyes"; then
			ACX_OPENSSL_FIPS
		else
			ACX_OPENSSL_EVPAESWRAP
		fi

		AC_MSG_CHECKING(for OpenSSL engines support)
		if test "x${enable_openssl_engines}" = "xyes"; then
			ACX_OPENSSL_ENGINES
			if test "x${have_lib_openssl_engines_support}" = "xyes"; then
				AC_MSG_RESULT([yes])
			else
				AC_MSG_RESULT([no])
				AC_DEFINE_UNQUOTED([WITHOUT_OPENSSL_ENGINES], [1],
					[Compile without OpenSSL engines support as it is unavailable])
			fi
		else
			AC_MSG_RESULT([disabled])
			AC_DEFINE([WITHOUT_OPENSSL_ENGINES], [1],
				[Compile without OpenSSL engines support as it is disabled])
		fi

		AC_DEFINE_UNQUOTED(
			[WITH_RAW_PSS],
			[1],
			[Compile with raw RSA PKCS PSS]
		)
		AC_DEFINE_UNQUOTED(
			[WITH_OPENSSL],
			[],
			[Compile with OpenSSL support]
		)

	elif test "x${crypto_backend}" = "xbotan"; then
		AC_MSG_RESULT(Botan)

		ACX_BOTAN(2,11,0)

		CRYPTO_INCLUDES=$BOTAN_CFLAGS
		CRYPTO_LIBS=$BOTAN_LIBS

		case "${enable_ecc}" in
			yes|detect) ACX_BOTAN_ECC;;
		esac
		case "${enable_ecc}-${have_lib_botan_ecc_support}" in
			yes-no) AC_MSG_ERROR([Botan library has no ECC support]);;
			detect-*) enable_ecc="${have_lib_botan_ecc_support}";;
		esac

		case "${enable_eddsa}" in
			yes|detect) ACX_BOTAN_EDDSA;;
		esac
		case "${enable_eddsa}-${have_lib_botan_eddsa_support}" in
			yes-no) AC_MSG_ERROR([Botan library has no EDDSA support]);;
			detect-*) enable_eddsa="${have_lib_botan_eddsa_support}";;
		esac

		if test	"x${enable_mldsa}" = "xyes"; then
            AC_MSG_ERROR([Botan does not support ML-DSA])
        fi

        if test "x${enable_mlkem}" = "xyes"; then
            AC_MSG_ERROR([Botan does not support ML-KEM])
        fi

		# Botan has supported SHA3 since well before its minimum required
		# version, so no version detection is needed.
		case "${enable_sha3}" in
			detect) enable_sha3="yes";;
		esac

		case "${enable_gost}" in
			yes|detect) ACX_BOTAN_GOST;;
		esac
		case "${enable_gost}-${have_lib_botan_gost_support}" in
			yes-no) AC_MSG_ERROR([Botan library has no GOST support]);;
			detect-*) enable_gost="${have_lib_botan_gost_support}";;
		esac

		if test	"x${enable_fips}" = "xyes"; then
			AC_MSG_ERROR([Botan does not support FIPS 140-2 mode])
		fi

		ACX_BOTAN_RFC5649
		ACX_BOTAN_RAWPSS

		AC_DEFINE_UNQUOTED(
			[WITH_BOTAN],
			[],
			[Compile with Botan support]
		)

	else
		AC_MSG_RESULT(Unknown)
		AC_MSG_ERROR([Crypto backend ${crypto_backend} not supported. Use openssl or botan.])
	fi

	AC_MSG_CHECKING(for ECC support)
	if test "x${enable_ecc}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_ECC],
			[],
			[Compile with ECC support]
		)
	else
		AC_MSG_RESULT(no)
	fi
	AM_CONDITIONAL([WITH_ECC], [test "x${enable_ecc}" = "xyes"])

	AC_MSG_CHECKING(for GOST support)
	if test "x${enable_gost}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_GOST],
			[],
			[Compile with GOST support]
		)
	else
		AC_MSG_RESULT(no)
	fi
	AM_CONDITIONAL([WITH_GOST], [test "x${enable_gost}" = "xyes"])

	AC_MSG_CHECKING(for EDDSA support)
	if test "x${enable_eddsa}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_EDDSA],
			[],
			[Compile with EDDSA support]
		)
	else
		AC_MSG_RESULT(no)
	fi
	AM_CONDITIONAL([WITH_EDDSA], [test "x${enable_eddsa}" = "xyes"])

	AC_MSG_CHECKING(for ML-DSA support)
	if test "x${enable_mldsa}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_ML_DSA],
			[],
			[Compile with ML-DSA support]
		)
	else
		AC_MSG_RESULT(no)
	fi
	AM_CONDITIONAL([WITH_ML_DSA], [test "x${enable_mldsa}" = "xyes"])

	AC_MSG_CHECKING(for ML-KEM support)
	if test "x${enable_mlkem}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_ML_KEM],
			[],
			[Compile with ML-KEM support]
		)
	else
		AC_MSG_RESULT(no)
	fi
	AM_CONDITIONAL([WITH_ML_KEM], [test "x${enable_mlkem}" = "xyes"])

	AC_MSG_CHECKING(for SHA3 support)
	if test "x${enable_sha3}" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE_UNQUOTED(
			[WITH_SHA3],
			[],
			[Compile with SHA3 support]
		)
	else
		AC_MSG_RESULT(no)
	fi
	AM_CONDITIONAL([WITH_SHA3], [test "x${enable_sha3}" = "xyes"])


	AC_SUBST(CRYPTO_INCLUDES)
	AC_SUBST(CRYPTO_LIBS)
	AM_CONDITIONAL([WITH_OPENSSL], [test "x${crypto_backend}" = "xopenssl"])
	AM_CONDITIONAL([WITH_BOTAN], [test "x${crypto_backend}" = "xbotan"])

])
