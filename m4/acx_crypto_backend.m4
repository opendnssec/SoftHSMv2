AC_DEFUN([ACX_CRYPTO_BACKEND],[

	# First check if we want to support ECC and GOST

	AC_ARG_ENABLE(ecc,
		AC_HELP_STRING([--enable-ecc],
			[Enable support for ECC (default enabled)]
		),
		[enable_ecc="${enableval}"],
		[enable_ecc="yes"]
	)
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

	AC_ARG_ENABLE(gost,
		AC_HELP_STRING([--enable-gost],
			[Enable support for GOST (default enabled)]
		),
		[enable_gost="${enableval}"],
		[enable_gost="yes"]
	)
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

	# Then check what crypto library we want to use

	AC_ARG_WITH(crypto-backend,
		AC_HELP_STRING([--with-crypto-backend],
			[Select crypto backend (openssl|botan)]
		),
		[crypto_backend="${withval}"],
		[crypto_backend="openssl"]
	)

	AC_MSG_CHECKING(for crypto backend)

	if test "x${crypto_backend}" = "xopenssl"; then
		AC_MSG_RESULT(OpenSSL)

		ACX_OPENSSL(1,0,0)

		CRYPTO_INCLUDES=$OPENSSL_INCLUDES
		CRYPTO_LIBS=$OPENSSL_LIBS

		if test "x${enable_ecc}" = "xyes"; then
			ACX_OPENSSL_ECC
		fi

		if test "x${enable_gost}" = "xyes"; then
			ACX_OPENSSL_GOST
		fi

		ACX_OPENSSL_RFC5649

		AC_DEFINE_UNQUOTED(
			[WITH_OPENSSL],
			[],
			[Compile with OpenSSL support]
		)

	elif test "x${crypto_backend}" = "xbotan"; then
		AC_MSG_RESULT(Botan)

		ACX_BOTAN(1,10,0)

		CRYPTO_INCLUDES=$BOTAN_INCLUDES
		CRYPTO_LIBS=$BOTAN_LIBS

		if test "x${enable_ecc}" = "xyes"; then
			ACX_BOTAN_ECC
		fi

		if test "x${enable_gost}" = "xyes"; then
			ACX_BOTAN_GOST
		fi

		ACX_BOTAN_RFC5649
		ACX_BOTAN_GNUMP

		AC_DEFINE_UNQUOTED(
			[WITH_BOTAN],
			[],
			[Compile with Botan support]
		)

	else
		AC_MSG_RESULT(Unknown)
		AC_MSG_ERROR([Crypto backend ${crypto_backend} not supported. Use openssl or botan.])
	fi

	AC_SUBST(CRYPTO_INCLUDES)
	AC_SUBST(CRYPTO_LIBS)
	AM_CONDITIONAL([WITH_OPENSSL], [test "x${crypto_backend}" = "xopenssl"])
	AM_CONDITIONAL([WITH_BOTAN], [test "x${crypto_backend}" = "xbotan"])

])
