# $Id$

AC_DEFUN([ACX_CRYPTO_BACKEND],[

	# First check if we want to support GOST

	AC_ARG_ENABLE(gost,
		AC_HELP_STRING([--enable-gost],
			[Enable support for GOST (default disabled)]
		),
		[enable_gost="${enableval}"],
		[enable_gost="no"]
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

		if test "x${enable_gost}" = "xyes"; then
			ACX_OPENSSL(1,0,0)
		else
			ACX_OPENSSL(0,9,8)
		fi

		CRYPTO_INCLUDES=$OPENSSL_INCLUDES
		CRYPTO_LIBS=$OPENSSL_LIBS

		AC_DEFINE_UNQUOTED(
			[WITH_OPENSSL],
			[],
			[Compile with OpenSSL support]
		)

	elif test "x${crypto_backend}" = "xbotan"; then
		AC_MSG_RESULT(Botan)

		if test "x${enable_gost}" = "xyes"; then
			ACX_BOTAN(1,9,7)
		else
			ACX_BOTAN(1,9,7)
		fi

		CRYPTO_INCLUDES=$BOTAN_INCLUDES
		CRYPTO_LIBS=$BOTAN_LIBS

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
